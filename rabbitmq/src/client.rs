//! RabbitMQ ChainNotfiy implementation

use common::try_spawn;
use enclose::enclose;
use ethcore::client::{BlockChainClient, BlockId, ChainNotify, ChainRouteType, NewBlocks};
use ethcore::miner;
use ethereum_types::H256;
use failure::{format_err, Error};
use futures::future::{err, lazy};
use handler::{Handler, Sender};

use parity_runtime::Executor;
use prometheus::{Counter, Opts, Encoder, TextEncoder};
use rabbitmq_adaptor::{ConfigUri, ConsumerResult, DeliveryExt, RabbitConnection, RabbitExt};
use serde::Deserialize;
use serde_json;
use std::sync::Arc;
use tokio::prelude::*;
use tokio::sync::mpsc::{channel, Sender as ChannelSender};
use types::{Block, BlockTransactions, Bytes, Log, RichBlock, Transaction};
use hyper::{header::CONTENT_TYPE, rt::Future, service::service_fn_ok, Body, Response, Server};

use DEFAULT_CHANNEL_SIZE;
use DEFAULT_REPLY_QUEUE;
use LOG_TARGET;
use NEW_BLOCK_EXCHANGE_NAME;
use NEW_BLOCK_ROUTING_KEY;
use OPERATION_ID;
use PUBLIC_TRANSACTION_QUEUE;
use TX_ERROR_EXCHANGE_NAME;
use TX_ERROR_ROUTING_KEY;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RabbitMqConfig {
	pub uri: String,
	pub prometheus_reporting_enabled: bool,
	pub prometheus_export_service_port: u16,
}

/// Eth PubSub implementation.
pub struct PubSubClient<C> {
	pub client: Arc<C>,
	pub sender: ChannelSender<Vec<u8>>,
}

#[derive(Deserialize)]
struct TransactionMessage {
	pub data: Bytes,
	pub transaction_hash: H256,
}

#[derive(Serialize)]
struct TransactionErrorMessage {
	pub transaction_hash: H256,
	pub error_message: String,
	pub error_type: ErrorType,
}

#[derive(Serialize)]
pub enum ErrorType {
	LocalTransactionError,
	TransactionRejected,
}

impl<C: 'static + miner::BlockChainClient + BlockChainClient> PubSubClient<C> {
	pub fn new(
		client: Arc<C>,
		miner: Arc<miner::Miner>,
		executor: Executor,
		config: RabbitMqConfig,
	) -> Result<Self, Error> {
		let (sender, receiver) = channel::<Vec<u8>>(DEFAULT_CHANNEL_SIZE);
		let sender_handler = Box::new(Sender::new(client.clone(), miner.clone()));
		let config_uri = ConfigUri::Uri(config.uri);

		let prometheus_reporting_enabled = config.prometheus_reporting_enabled;
		let prometheus_export_service_port = config.prometheus_export_service_port;

		let export_service_address = ([127, 0, 0, 1], prometheus_export_service_port).into();
		info!(
			"Prometheus export service listening at address: {:?}",
			export_service_address
		);

		let new_block_counter =
			Counter::with_opts(Opts::new("new_block_counter", "New block count")).unwrap();

		let export_service_handler = || {
			let encoder = TextEncoder::new();
			service_fn_ok(move |_request| {

				let metric_families = prometheus::gather();
				let mut buffer = vec![];
				encoder.encode(&metric_families, &mut buffer).unwrap();

				let response = Response::builder()
					.status(200)
					.header(CONTENT_TYPE, encoder.format_type())
					.body(Body::from(buffer))
					.unwrap();

				response
			})
		};

		let export_service =  Server::bind(&export_service_address)
        .serve(export_service_handler)
        .map_err(|e| eprintln!("Server error: {}", e));

		executor.spawn(lazy(move || {
			let rabbit = RabbitConnection::new(config_uri, None, DEFAULT_REPLY_QUEUE);
			// Consume to public transaction messages
			try_spawn(
				rabbit
					.clone()
					.register_consumer(
						PUBLIC_TRANSACTION_QUEUE.to_string(),
						enclose!((rabbit) move |message| {
							let operation_id = message.get_header(OPERATION_ID);
							if operation_id.is_none() {
								return Box::new(err(format_err!("Missing protocol-id header")));
							}
							let operation_id = operation_id.unwrap();
							let payload = std::str::from_utf8(&message.data);
							if payload.is_err() {
								return Box::new(err(format_err!("Could not parse AMQP message")));
							}
							let payload = payload.unwrap();
							let transaction_message = serde_json::from_str(payload);
							if transaction_message.is_err() {
								return Box::new(err(format_err!("Could not deserialize AMQP message payload")));
							}
							let transaction_message: TransactionMessage = transaction_message.unwrap();
							let transaction_hash = transaction_message.transaction_hash;
							Box::new(sender_handler.send_transaction(transaction_message.data)
								.map(|_| ())
								.into_future()
								.or_else(enclose!((rabbit) move |error| {
									let tx_error = TransactionErrorMessage {
										transaction_hash,
										error_message: format!("{}", error),
										error_type: ErrorType::LocalTransactionError,
									};
									let serialized_message = serde_json::to_string(&tx_error).unwrap();
									rabbit.clone().publish(
										TX_ERROR_EXCHANGE_NAME.to_string(),
										TX_ERROR_ROUTING_KEY.to_string(),
										serialized_message.into(),
										vec![(OPERATION_ID.to_string(), operation_id)],
									).map(|_| ())
								}))
								.map(|_| ConsumerResult::ACK)
							)
						}),
					)
					.map_err(Error::from)
					.map(|_| ()),
			);

			// Send new block messages
			receiver
				.for_each(enclose!((rabbit) move |message| {
					new_block_counter.inc();
					try_spawn(
					rabbit.clone()
					.publish(
						NEW_BLOCK_EXCHANGE_NAME.to_string(),
						NEW_BLOCK_ROUTING_KEY.to_string(),
						message,
						vec![],
					)
					.map(|_| ()));
					Ok(())
				}))
				.map_err(|e| {
					error!(
						target: LOG_TARGET,
						"failed to send message to channel: {:?}", e
					);
				})
		}));
		if prometheus_reporting_enabled {
			executor.spawn(export_service);
		}
		Ok(Self { client, sender })
	}
}

impl<C: BlockChainClient> ChainNotify for PubSubClient<C> {
	fn new_blocks(&self, new_blocks: NewBlocks) {
		fn cast<O, T: Copy + Into<O>>(t: &T) -> O {
			(*t).into()
		}

		let blocks = new_blocks
			.route
			.route()
			.iter()
			.filter_map(|&(hash, ref typ)| match typ {
				&ChainRouteType::Retracted => None,
				&ChainRouteType::Enacted => self.client.block(BlockId::Hash(hash)),
			})
			.map(|block| {
				let hash = block.hash();
				let header = block.decode_header();
				let receipts = self
					.client
					.localized_block_receipts(BlockId::Number(header.number()))
					.expect("Receipts from the block");
				let extra_info = self
					.client
					.block_extra_info(BlockId::Hash(hash))
					.expect("Extra info from block");
				RichBlock {
					inner: Block {
						hash: Some(hash.into()),
						size: Some(block.rlp().as_raw().len().into()),
						parent_hash: cast(header.parent_hash()),
						uncles_hash: cast(header.uncles_hash()),
						author: cast(header.author()),
						miner: cast(header.author()),
						state_root: cast(header.state_root()),
						receipts_root: cast(header.receipts_root()),
						number: Some(header.number().into()),
						gas_used: cast(header.gas_used()),
						gas_limit: cast(header.gas_limit()),
						logs_bloom: Some(cast(header.log_bloom())),
						timestamp: header.timestamp().into(),
						difficulty: cast(header.difficulty()),
						total_difficulty: None,
						seal_fields: header.seal().into_iter().cloned().map(Into::into).collect(),
						uncles: block.uncle_hashes().into_iter().map(Into::into).collect(),
						logs: receipts
							.into_iter()
							.flat_map(|receipt| receipt.logs)
							.map(Log::from)
							.collect(),
						transactions: BlockTransactions::Full(
							block
								.view()
								.localized_transactions()
								.into_iter()
								.map(Transaction::from_localized)
								.collect(),
						),
						transactions_root: cast(header.transactions_root()),
						extra_data: header.extra_data().clone().into(),
					},
					extra_info: extra_info.clone(),
				}
			})
			.collect::<Vec<_>>();

		for ref rich_block in blocks {
			let serialized_block = serde_json::to_string(&rich_block).unwrap();
			info!(target: LOG_TARGET, "Serialized: {:?} ", serialized_block);
			&self
				.sender
				.clone()
				.try_send(serialized_block.into())
				.unwrap();
		}
	}
}
