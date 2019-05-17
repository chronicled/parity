//! RabbitMQ ChainNotfiy implementation

use enclose::enclose;
use ethcore::client::{BlockChainClient, BlockId, ChainNotify, ChainRouteType, NewBlocks};
use ethcore::miner;
use failure::{Error, ResultExt};
use futures::future::lazy;
use handler::{Handler, Sender};
use parity_runtime::Executor;
use rabbitmq_adaptor::{RabbitConnection, RabbitExt};
use serde::Deserialize;
use serde_json;
use std::sync::Arc;
use tokio::prelude::*;
use tokio::sync::mpsc::{channel, Sender as ChannelSender};
use types::{Block, BlockTransactions, Bytes, Log, RichBlock, Transaction};

use DEFAULT_CHANNEL_SIZE;
use DEFAULT_REPLY_QUEUE;
use LOG_TARGET;
use NEW_BLOCK_EXCHANGE_NAME;
use NEW_BLOCK_ROUTING_KEY;
use PUBLIC_TRANSACTION_QUEUE;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RabbitMqConfig {
	pub hostname: String,
	pub port: u16,
}

/// Eth PubSub implementation.
pub struct PubSubClient<C> {
	pub client: Arc<C>,
	pub sender: ChannelSender<Vec<u8>>,
}

#[derive(Deserialize)]
struct TransactionMessage {
	pub data: Bytes,
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

		executor.spawn(lazy(move || {
			let rabbit = RabbitConnection::new(&config.hostname, config.port, DEFAULT_REPLY_QUEUE);
			// Consume to public transaction messages
			tokio::spawn(
				rabbit
					.clone()
					.register_consumer(
						PUBLIC_TRANSACTION_QUEUE.to_string(),
						enclose!(() move |message| {
							let payload = std::str::from_utf8(&message.data)?;
							debug!(target: LOG_TARGET, "got message: {:?}", payload);
							let transaction_message: TransactionMessage = serde_json::from_str(payload)
								.context(format!("Couldn't parse public transaction: {}", payload.to_string()))?;
							sender_handler.send_transaction(transaction_message.data)
								.context(format!("Failed to send transaction"))?;
							Ok(())
						}),
					)
					.map_err(|error| panic!("Error in consumer {:?}", error))
					.map(|_| ()),
			);

			// Send new block messages
			receiver
				.for_each(enclose!((rabbit) move |message| {
					tokio::spawn(
					rabbit.clone()
					.publish(
						NEW_BLOCK_EXCHANGE_NAME.to_string(),
						NEW_BLOCK_ROUTING_KEY.to_string(),
						message,
						vec![],
					)
					.map(|_| ())
					.map_err(|_| ()));
					Ok(())
				}))
				.map_err(|e| {
					error!(
						target: LOG_TARGET,
						"failed to send message to channel: {:?}", e
					)
				})
		}));

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
