//! RabbitMQ ChainNotfiy implementation

use byteorder::{LittleEndian, ByteOrder};
use common::try_spawn;
use enclose::enclose;
use ethcore::client::{BlockChainClient, BlockId, ChainNotify, ChainRoute, ChainRouteType, NewBlocks};
use ethcore::miner;
use ethereum_types::H256;
use failure::{format_err, Error};
use futures::future::{err, lazy};
use handler::{Handler, Sender};
use hyper::{header::CONTENT_TYPE, rt::Future, service::service_fn_ok, Body, Response, Server};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_rocksdb::Database;
use parity_runtime::Executor;
use prometheus::{Counter, Encoder, TextEncoder};
use rabbitmq_adaptor::{ConfigUri, ConsumerResult, DeliveryExt, RabbitConnection, RabbitExt};
use serde::Deserialize;
use serde_json;
use std::path::Path;
use std::sync::Arc;
use std::time;
use tokio::prelude::*;
use tokio::sync::mpsc::{
	channel, Sender as ChannelSender, Receiver as ChannelReceiver
};
use types::{Block, BlockTransactions, Bytes, Log, RichBlock, Transaction};

use DB_NAME;
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
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct PrometheusExportServiceConfig {
	pub prometheus_export_service: bool,
	pub prometheus_export_service_port: u16,
}

/// Eth PubSub implementation.
pub struct PubSubClient<C> {
	pub client: Arc<C>,
	pub sender: ChannelSender<Vec<u8>>,
	pub database: Arc<KeyValueDB>,
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

lazy_static! {
	static ref NEW_BLOCK_COUNTER: Counter = register_counter!(opts!(
		"new_blocks",
		"Total number of new block pubsub messages received."
	))
	.unwrap();
}

impl<C: 'static + miner::BlockChainClient + BlockChainClient> PubSubClient<C> {
	pub fn new(
		client: Arc<C>,
		miner: Arc<miner::Miner>,
		executor: Executor,
		client_path: Option<&str>,
		config: RabbitMqConfig,
		prometheus_export_service_config: PrometheusExportServiceConfig
	) -> Result<Self, Error> {
		let (sender, receiver) = channel::<Vec<u8>>(DEFAULT_CHANNEL_SIZE);
		let config_uri = ConfigUri::Uri(config.uri);
		let db_path = Path::new(client_path.ok_or_else(|| format_err!("Client path does not exist"))?)
			.join(DB_NAME);
		let db_path = db_path.to_str().ok_or_else(|| format_err!("Invalid rabbitmq db path"))?;
		let database = Arc::new(Database::open_default(db_path)?);

		let pub_sub_client = Self { client, sender, database };
		pub_sub_client.serve(executor.clone(), receiver, miner, config_uri)?;
		pub_sub_client.send_missed_blocks()?;
		pub_sub_client.start_monitoring(executor, prometheus_export_service_config)?;
		Ok(pub_sub_client)
	}

	fn serve(
		&self,
		executor: Executor,
		receiver: ChannelReceiver<Vec<u8>>,
		miner: Arc<miner::Miner>,
		config_uri: ConfigUri
	) -> Result<(), Error> {
		let sender_handler = Box::new(Sender::new(self.client.clone(), miner.clone()));
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
								return Box::new(err(format_err!("Missing operation-id header")));
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
					NEW_BLOCK_COUNTER.inc();
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
		Ok(())
	}

	pub fn send_missed_blocks(&self) -> Result<(), Error> {
		let latest_sent_block: u64 = self.database.get(None, b"latest")
			.expect("low-level database error")
			.and_then(|val| {
				Some(LittleEndian::read_u64(&val[..]))
			})
			.unwrap_or(0u64);
		let latest_blockchain_block = self.client.block(BlockId::Latest)
			.ok_or_else(|| format_err!("Could not get the latest block from the Blockchain database"))?;
		let latest_blockchain_block_number: u64 = latest_blockchain_block.decode_header().number();
		if latest_sent_block < latest_blockchain_block_number {
			let mut route: Vec<(H256, ChainRouteType)> = vec![];
			for new_block_number in latest_sent_block..latest_blockchain_block_number {
				let new_block = self.client.block(BlockId::Number(new_block_number + 1))
					.ok_or_else(|| format_err!("Could not retreive raw block data for block: {}", new_block_number + 1))?;
				let new_block_hash = new_block.hash();
				route.push((new_block_hash, ChainRouteType::Enacted));
			}

			let chain_route = ChainRoute::new(route);
			let new_blocks = NewBlocks::new(vec![], vec![], chain_route, vec![], vec![], time::Duration::from_secs(0), false);
			self.new_blocks(new_blocks);
		}
		Ok(())
	}

	fn start_monitoring(
		&self, executor: Executor,
		prometheus_export_service_config: PrometheusExportServiceConfig
	) -> Result<(), Error> {
		let export_service_enabled = prometheus_export_service_config.prometheus_export_service;

		if export_service_enabled {
			let export_service_port = prometheus_export_service_config.prometheus_export_service_port;

			let export_service_address = ([127, 0, 0, 1], export_service_port).into();
			info!(
				"Prometheus export service listening at address: {:?}",
				export_service_address
			);

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

			let export_service = Server::bind(&export_service_address)
				.serve(export_service_handler)
				.map_err(|e| eprintln!("Server error: {}", e));
			executor.spawn(export_service);
		}
		Ok(())
	}
}

impl<C: BlockChainClient> ChainNotify for PubSubClient<C> {
	fn new_blocks(&self, new_blocks: NewBlocks) {
		fn cast<O, T: Copy + Into<O>>(t: &T) -> O {
			(*t).into()
		}

		let mut highest_block_number: u64 = 0;
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
				let block_number = header.number();
				if header.number() > highest_block_number {
					highest_block_number = block_number;
				}
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
						number: Some(block_number.into()),
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
		let mut transaction = DBTransaction::new();
		transaction.put(None, b"latest", &highest_block_number.to_le_bytes());
		self.database.write(transaction).map_err(|err| {
			error!("Error writing latest block number in RocksDB: {}", err);
			()
		});
	}
}
