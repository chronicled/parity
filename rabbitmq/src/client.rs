//! RabbitMQ ChainNotfiy implementation

use common_types::{BlockNumber, ids::TransactionId, receipt::TransactionOutcome};
use byteorder::{LittleEndian, ByteOrder};
use boolinator::Boolinator;
use common::{handle_fatal_error, try_spawn};
use enclose::enclose;
use ethcore::client::{BlockChainClient, BlockId, ChainNotify, ChainRouteType, NewBlocks};
use ethcore::miner;
use ethereum_types::H256;
use failure::{format_err, Error};
use futures::future::{ok, err, lazy, loop_fn, Future, Loop};
use handler::{Handler, Sender};
use hyper::{header::CONTENT_TYPE, service::service_fn_ok, Body, Response, Server};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_rocksdb::Database;
use parity_runtime::Executor;
use prometheus::{Counter, Encoder, Gauge, TextEncoder};
use rabbitmq_adaptor::{ConfigUri, ConsumerResult, DeliveryExt, RabbitConnection, RabbitExt};
use serde::Deserialize;
use serde_json;
use sync::SyncProvider;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::*;
use tokio::sync::mpsc::{
	channel, Sender as ChannelSender
};
use types::{Block, BlockTransactions, Bytes, Log, RichBlock, Trace, Transaction};

use DB_NAME;
use START_FROM_INDEX;
use DEFAULT_CHANNEL_SIZE;
use RETRACTED_CHANNEL_SIZE;
use DEFAULT_REPLY_QUEUE;
use LOG_TARGET;
use NEW_BLOCK_EXCHANGE_NAME;
use NEW_BLOCK_ROUTING_KEY;
use RETRACTED_BLOCK_ROUTING_KEY;
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
	pub blockchain_client: Arc<C>,
	pub sync: Arc<SyncProvider>,
	pub enacted_sender: ChannelSender<BlockNumber>,
	pub retracted_sender: ChannelSender<H256>,
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
	static ref SENT_BLOCKS_COUNTER: Counter = register_counter!(opts!(
		"sent_blocks",
		"Total number of new blocks published to the RabbitMQ interface since parity started."
	))
	.unwrap();
	static ref CONNECTED_PEERS_GAUGE: Gauge = register_gauge!(opts!(
		"connected_peers",
		"Number of connected peers."
	))
	.unwrap();
	static ref LATEST_BLOCK_RECEIVED: Gauge = register_gauge!(opts!(
		"latest_block",
		"Block number of the latest imported block."
	))
	.unwrap();
}

impl<C: 'static + miner::BlockChainClient + BlockChainClient> PubSubClient<C> {
	pub fn new(
		blockchain_client: Arc<C>,
		miner: Arc<miner::Miner>,
		sync_provider: Arc<SyncProvider>,
		executor: Executor,
		client_path: Option<&str>,
		config: RabbitMqConfig,
		prometheus_export_service_config: PrometheusExportServiceConfig
	) -> Result<Self, Error> {
		let (enacted_sender, enacted_receiver) = channel::<BlockNumber>(DEFAULT_CHANNEL_SIZE);
		let (retracted_sender, retracted_receiver) = channel::<H256>(RETRACTED_CHANNEL_SIZE);
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
				retracted_receiver
					.map_err(Error::from)
					.and_then(enclose!((client) move |block_hash| {
						construct_retracted_block(block_hash, client.clone())
							.ok_or(format_err!("Could not serialize retracted block"))
					}))
					.for_each(enclose!((rabbit, client) move |serialized_block| {
						rabbit.clone()
						.publish(
							NEW_BLOCK_EXCHANGE_NAME.to_string(),
							RETRACTED_BLOCK_ROUTING_KEY.to_string(),
							serialized_block.into(),
							vec![],
						)
						.map_err(Error::from)
						.map(|_| ())
					}))
					.map_err(Error::from),
			);

			enacted_receiver
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

		let pubsub_client = PubSubClient {
			blockchain_client,
			sync: sync_provider.clone(),
			enacted_sender,
			retracted_sender,
			database,
		};
		pubsub_client.start_monitoring(executor, prometheus_export_service_config)?;

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

			let export_service_address = ([0, 0, 0, 0], export_service_port).into();
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
			SENT_BLOCKS_COUNTER.inc();
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
	let receipts = client.localized_block_receipts(BlockId::Number(block_number))?;
	let extra_info = client.block_extra_info(BlockId::Hash(hash))?;

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
						let traces = match client.transaction_traces(transaction_id) {
							Some(traces) => traces.into_iter().map(Trace::from).collect(),
							None => vec![],
						};
						(tx, outcome, traces)
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

pub fn construct_retracted_block<C: BlockChainClient>(
	block_hash: H256,
	client: Arc<C>,
) -> Option<String> {
	fn cast<O, T: Copy + Into<O>>(t: &T) -> O {
		(*t).into()
	}

	let block = client.block(BlockId::Hash(block_hash))?;

	let header = block.decode_header();

	let rich_block = RichBlock {
		inner: Block {
			hash: Some(block_hash.into()),
			size: Some(block.rlp().as_raw().len().into()),
			parent_hash: cast(header.parent_hash()),
			uncles_hash: cast(header.uncles_hash()),
			author: cast(header.author()),
			miner: cast(header.author()),
			state_root: cast(header.state_root()),
			receipts_root: cast(header.receipts_root()),
			number: Some(cast(&header.number())),
			gas_used: cast(header.gas_used()),
			gas_limit: cast(header.gas_limit()),
			logs_bloom: Some(cast(header.log_bloom())),
			timestamp: header.timestamp().into(),
			difficulty: cast(header.difficulty()),
			total_difficulty: None,
			seal_fields: header.seal().into_iter().cloned().map(Into::into).collect(),
			uncles: block.uncle_hashes().into_iter().map(Into::into).collect(),
			logs: vec![],
			transactions: BlockTransactions::Hashes(vec![]),
			transactions_root: cast(header.transactions_root()),
			extra_data: header.extra_data().clone().into(),
		},
		extra_info: BTreeMap::default(),
	};
	let serialized_block = serde_json::to_string(&rich_block).unwrap();
	info!(
		target: LOG_TARGET,
		"Serialized retracted block: {:?} ", serialized_block
	);
	Some(serialized_block)
}

impl<C: BlockChainClient> ChainNotify for PubSubClient<C> {
	fn new_blocks(&self, new_blocks: NewBlocks) {
		let connected_peers = self.sync.status().num_peers;
		CONNECTED_PEERS_GAUGE.set(connected_peers as f64);
		let enacted_blocks = new_blocks
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
		let retracted_blocks = new_blocks
			.route
			.route()
			.iter()
			.filter_map(|&(hash, ref typ)| match typ {
				&ChainRouteType::Retracted => Some(hash),
				&ChainRouteType::Enacted => None,
			})
			.collect::<Vec<_>>();


		enacted_blocks.into_iter().for_each(|block| {
			LATEST_BLOCK_RECEIVED.set(block as f64);
			&self
				.enacted_sender
				.clone()
				.try_send(block)
				.map_err(|err| {
					if err.is_full() {
						trace!(target: LOG_TARGET, "MPSC channel is full: {:?}, Receiver is already processing new block messages", err);
					} else {
						panic!(err)
					}
				});
		});
		retracted_blocks.into_iter().for_each(|block_hash| {
			&self.retracted_sender.clone().try_send(block_hash)
			.map_err(|err| {
				if err.is_full() {
					trace!(target: LOG_TARGET, "MPSC channel is full: {:?}, Receiver is already processing new block messages", err);
				} else {
					panic!(err)
				}
			});
		})
	}
}
