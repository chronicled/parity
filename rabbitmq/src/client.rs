//! RabbitMQ ChainNotfiy implementation

use common_types::{BlockNumber, ids::TransactionId, receipt::TransactionOutcome};
use byteorder::{LittleEndian, ByteOrder};
use boolinator::Boolinator;
use common::{handle_fatal_error, try_spawn};
use enclose::enclose;
use ethcore::client::{BlockChainClient, BlockId, CallAnalytics, ChainNotify, ChainRouteType, NewBlocks};
use ethcore::miner;
use ethereum_types::{H160, H256, U256};
use failure::{format_err, Error};
use futures::future::{ok, err, lazy, loop_fn, Future, Loop};
use handler::{Handler, Sender};
use hyper::{header::CONTENT_TYPE, service::service_fn_ok, Body, Response, Server};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_rocksdb::Database;
use parity_runtime::Executor;
use prometheus::{Counter, Encoder, TextEncoder};
use rabbitmq_adaptor::{ConfigUri, ConsumerResult, DeliveryExt, RabbitConnection, RabbitExt};
use serde::Deserialize;
use serde_json;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::*;
use tokio::sync::mpsc::{
	channel, Sender as ChannelSender
};
use types::{Block, BlockTransactions, Bytes, Log, RichBlock, TraceResults, Transaction};

use DB_NAME;
use START_FROM_INDEX;
use DEFAULT_CHANNEL_SIZE;
use DEFAULT_REPLY_QUEUE;
use LOG_TARGET;
use NEW_BLOCK_EXCHANGE_NAME;
use NEW_BLOCK_ROUTING_KEY;

use GET_NONCE_QUEUE;
use OPERATION_ID;
use PUBLIC_TRANSACTION_QUEUE;
use TX_ERROR_EXCHANGE_NAME;
use TX_ERROR_ROUTING_KEY;

const DEFAULT_CALL_ANALYTICS: CallAnalytics = CallAnalytics {
	transaction_tracing: true,
	vm_tracing: false,
	state_diffing: false,
};

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
	pub blockchain_client: Arc<C>,
	pub sender: ChannelSender<BlockNumber>,
	pub database: Arc<KeyValueDB>,
}

#[derive(Deserialize)]
struct TransactionMessage {
	pub data: Bytes,
	pub transaction_hash: H256,
}

#[derive(Deserialize)]
struct NonceRequest {
	pub address: H160,
}

#[derive(Serialize)]
struct NonceResponse {
	pub nonce: Option<U256>,
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
		blockchain_client: Arc<C>,
		miner: Arc<miner::Miner>,
		executor: Executor,
		client_path: Option<&str>,
		config: RabbitMqConfig,
		prometheus_export_service_config: PrometheusExportServiceConfig
	) -> Result<Self, Error> {
		let (sender, receiver) = channel::<BlockNumber>(DEFAULT_CHANNEL_SIZE);
		let config_uri = ConfigUri::Uri(config.uri);
		let db_path = Path::new(client_path.ok_or_else(|| format_err!("Client path does not exist"))?)
			.join(DB_NAME);
		let db_path = db_path.to_str().ok_or_else(|| format_err!("Invalid rabbitmq db path"))?;
		let database = Arc::new(Database::open_default(db_path)?);

		let sender_handler = Box::new(Sender::new(blockchain_client.clone(), miner.clone()));

		let db = database.clone();
		let client = blockchain_client.clone();

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

			try_spawn(
				rabbit
					.clone()
					.register_consumer(
						GET_NONCE_QUEUE.to_string(),
						enclose!((rabbit, client) move |message| {
							let payload = std::str::from_utf8(&message.data)
								.expect("Could not parse AMQP message");
							let nonce_request: NonceRequest = serde_json::from_str(payload)
								.expect("Could not deserialize AMQP message payload");
							let nonce_result = client.nonce(&nonce_request.address, BlockId::Latest);
							let nonce_response = NonceResponse {
								nonce: nonce_result
							};
							let serialized_message = serde_json::to_string(&nonce_response).unwrap();
							Box::new(rabbit.clone()
							.rpc_response(
								&message,
								serialized_message.into(),
								vec![],
							)
							.map_err(handle_fatal_error)
							.map_err(|_| format_err!("Could not send RPC response to RabbitMQ"))
							.map(|_| ConsumerResult::ACK)
							)
						}),
					)
					.map_err(Error::from)
					.map(|_| ()),
			);

			receiver
				.map_err(|err| handle_fatal_error(err.into()))
				.for_each(enclose!((db, client, rabbit) move |block_number| {
					loop_fn((db.clone(), client.clone(), rabbit.clone()), move |(db, client, rabbit)| {
						let mut start_from_index: u64 = db.get(None, START_FROM_INDEX)
							.expect("low-level database error")
							.and_then(|val| {
								Some(LittleEndian::read_u64(&val[..]))
							})
							.unwrap_or(0u64);
						let mut serialized_block = String::default();
						let mut should_break = false;
						let mut should_send = true;

						if start_from_index < (block_number - 1) {
							start_from_index += 1;
						} else {
							start_from_index = block_number;
							should_break = true;
						}
						match construct_new_block(start_from_index, client.clone()) {
							Some(serialized_data) => {
								serialized_block = serialized_data;
							},
							None => {
								should_break = true;
								should_send = false;
							}
						};

						should_send.ok_or(()).into_future()
						.and_then(enclose!((db, rabbit) move |_| {
							publish_new_block(db.clone(), rabbit.clone(), serialized_block.into(), start_from_index)
						}))
						.or_else(move |_| {
							should_break = true;
							ok(())
						})
						.and_then(move |_| {
							if should_break {
								Ok(Loop::Break(()))
							} else {
								Ok(Loop::Continue((db, client, rabbit)))
							}
						})
					})
				}))
		}));
		let pubsub_client = PubSubClient { blockchain_client, sender, database };
		pubsub_client.start_monitoring(executor, prometheus_export_service_config);

		Ok(pubsub_client)
	}

	fn start_monitoring(
		&self,
		executor: Executor,
		prometheus_export_service_config: PrometheusExportServiceConfig
	) -> Result<(), Error> {
		let export_service_enabled = prometheus_export_service_config.prometheus_export_service;

		if export_service_enabled {
			let export_service_port = prometheus_export_service_config.prometheus_export_service_port;

			let export_service_address = ([127, 0, 0, 1], export_service_port).into();
			info!(
				target: LOG_TARGET,
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

fn publish_new_block(
	database: Arc<KeyValueDB>,
	rabbit: RabbitConnection,
	serialized_message: Vec<u8>,
	block_number: u64
) ->  Box<dyn Future<Item = (), Error = ()> + Send> {
		Box::new(rabbit.clone()
		.publish(
			NEW_BLOCK_EXCHANGE_NAME.to_string(),
			NEW_BLOCK_ROUTING_KEY.to_string(),
			serialized_message,
			vec![],
		)
		.map_err(|err| {
			info!(target: LOG_TARGET, "Error publishing: {}", err);
			handle_fatal_error(err);
		})
		.timeout(Duration::from_secs(10))
		.map_err(|_| ())
		.map(move |_| {
			info!(target: LOG_TARGET, "Block message published: {:?}", block_number);
			()
		})
		.and_then(move |_| {
			NEW_BLOCK_COUNTER.inc();
			info!(target: LOG_TARGET, "Update block status in RocksDB: {:?}", block_number);
			let mut transaction = DBTransaction::new();
			transaction.put(None, START_FROM_INDEX, &(block_number).to_le_bytes());
			database.clone().write(transaction).map_err(|err| {
				handle_fatal_error(err.into());
			});
			ok(())
		}))
}

pub fn construct_new_block<C: BlockChainClient>(block_number: BlockNumber, client: Arc<C>) -> Option<String> {
	fn cast<O, T: Copy + Into<O>>(t: &T) -> O {
		(*t).into()
	}

	let block = client.block(BlockId::Number(block_number))?;

	let hash = block.hash();
	let header = block.decode_header();
	let receipts = client
		.localized_block_receipts(BlockId::Number(header.number()))?;
	let extra_info = client
		.block_extra_info(BlockId::Hash(hash))?;

	let rich_block = RichBlock {
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
					.map(|tx| {
						let transaction_id = TransactionId::Location(BlockId::Number(tx.block_number), tx.transaction_index);
						let outcome: Option<TransactionOutcome> = match client.transaction_receipt(transaction_id.clone()) {
							Some(receipt) => Some(receipt.outcome),
							None => None
						};
						let trace = client.replay(transaction_id, DEFAULT_CALL_ANALYTICS)
							.map(TraceResults::from)
							.ok();
						(tx, outcome, trace)
					})
					.map(Transaction::from_localized)
					.collect(),
			),
			transactions_root: cast(header.transactions_root()),
			extra_data: header.extra_data().clone().into(),
		},
		extra_info: extra_info.clone(),
	};
	let serialized_block = serde_json::to_string(&rich_block).unwrap();
	info!(target: LOG_TARGET, "Serialized: {:?} ", serialized_block);
	Some(serialized_block)
}

impl<C: BlockChainClient> ChainNotify for PubSubClient<C> {
	fn new_blocks(&self, new_blocks: NewBlocks) {
		let blocks = new_blocks
			.route
			.route()
			.iter()
			.filter_map(|&(hash, ref typ)| match typ {
				&ChainRouteType::Retracted => None,
				&ChainRouteType::Enacted => self.blockchain_client.block(BlockId::Hash(hash)),
			})
			.map(|block| {
				let header = block.decode_header();
				header.number()
			})
			.collect::<Vec<_>>();

		blocks.into_iter().for_each(|block| {
			&self
				.sender
				.clone()
				.try_send(block)
				.map_err(|err| {
					if err.is_full() {
						info!(target: LOG_TARGET, "MPSC channel is full: {:?}, Reciever is already processing new block messages", err);
					} else {
						panic!(err)
					}
				});
		});
	}
}
