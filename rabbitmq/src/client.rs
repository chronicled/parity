//! RabbitMQ ChainNotfiy implementation

use std::sync::Arc;
use serde_json;
use interface::Interface;
use ethcore::client::{BlockChainClient, ChainNotify, NewBlocks, ChainRouteType, BlockId};
use types::{Block, BlockTransactions, RichBlock, Transaction};

use NEW_BLOCK_EXCHANGE_NAME;
use NEW_BLOCK_ROUTING_KEY;

/// Eth PubSub implementation.
pub struct PubSubClient<C, I> {
	pub client: Arc<C>,
	pub interface: I,
}

impl<C: BlockChainClient, I:  Interface + Sync + Send> ChainNotify for PubSubClient<C, I> {
	fn new_blocks(&self, new_blocks: NewBlocks) {
		fn cast<O, T: Copy + Into<O>>(t: &T) -> O {
			(*t).into()
		}

		let blocks = new_blocks.route.route()
			.iter()
			.filter_map(|&(hash, ref typ)| {
				match typ {
					&ChainRouteType::Retracted => None,
					&ChainRouteType::Enacted => self.client.block(BlockId::Hash(hash))
				}
			})
			.map(|block| {
				let hash = block.hash();
				let header = block.decode_header();
				let extra_info = self.client.block_extra_info(BlockId::Hash(hash)).expect("Extra info from block");
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
						transactions: BlockTransactions::Full(block.view().localized_transactions().into_iter().map(Transaction::from_localized).collect()),
						transactions_root: cast(header.transactions_root()),
						extra_data: header.extra_data().clone().into(),
					},
					extra_info: extra_info.clone(),
				}
			})
			.collect::<Vec<_>>();

		for ref rich_block in blocks {
			let serialized_block = serde_json::to_string(&rich_block).unwrap();
			println!("Serialized: {:?}", serialized_block);
			self.interface.topic_publish(serialized_block, NEW_BLOCK_EXCHANGE_NAME, NEW_BLOCK_ROUTING_KEY);
		}
	}
}
