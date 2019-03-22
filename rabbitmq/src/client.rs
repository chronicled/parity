//! RabbitMQ ChainNotfiy implementation

use enclose::enclose;
use ethcore::client::{BlockChainClient, BlockId, ChainNotify, ChainRouteType, NewBlocks};
use ethcore::miner;
use failure::Error;
use futures::future::{lazy, Executor, Future};
use handler::{Handler, Sender};
use interface::RabbitMqConfig;
use rabbitmq_adaptor::{RabbitConnection, RabbitExt};
use serde_json;
use std::sync::Arc;
use tokio::runtime::current_thread::Runtime;
use types::{Block, BlockTransactions, RichBlock, Transaction, Log};

use LOG_TARGET;
use NEW_BLOCK_EXCHANGE_NAME;
use NEW_BLOCK_ROUTING_KEY;
use PUBLIC_TRANSACTION_QUEUE;
use TRANSACTION_CONSUMER;

/// Eth PubSub implementation.
pub struct PubSubClient<C> {
	pub client: Arc<C>,
	rabbit: RabbitConnection,
}

impl<C: 'static + miner::BlockChainClient + BlockChainClient> PubSubClient<C> {
	pub fn new(client: Arc<C>, conf: RabbitMqConfig) -> Result<Self, Error> {
		let rabbit = RabbitConnection::new("127.0.0.1", 5672);
		Ok(Self {
			client,
			rabbit,
		})
	}

	pub fn transaction_subscriber(&self, miner: Arc<miner::Miner>) -> Result<(), Error> {
		let sender_handler = Box::new(Sender::new(self.client.clone(), miner.clone()));
		let mut runtime = Runtime::new().unwrap();
		let result = runtime.block_on(lazy(move || {
			// Consume to public transaction messages
			tokio::spawn(
				self.rabbit.clone()
					.register_consumer(
						PUBLIC_TRANSACTION_QUEUE.to_string(),
						enclose!(() move |message| {
							let payload = std::str::from_utf8(&message.data).unwrap();
							debug!(target: LOG_TARGET, "got message: {:?}", payload);
							if let Err(e) = sender_handler.send_transaction(&payload) {
								error!(target: LOG_TARGET, "failed to send transaction: {:?}", e);
							}
							true
						}),
					)
					.map_err(|_| ()),
			)
		}));
		Ok(())
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
				let receipts =  self.client.localized_block_receipts(BlockId::Number(header.number()))
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
						logs: receipts.into_iter().flat_map(|receipt| receipt.logs).map(Log::from).collect(),
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
			&self.rabbit.clone().publish(
				NEW_BLOCK_EXCHANGE_NAME,
				NEW_BLOCK_ROUTING_KEY,
				serialized_block.into(),
			);
		}
	}
}
