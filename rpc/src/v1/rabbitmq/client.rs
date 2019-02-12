// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! RabbitMQ ChainNotfiy implementation

use std::sync::Arc;
use serde_json;
use super::interface::RabbitMqInterface;


use ethcore::client::{BlockChainClient, ChainNotify, NewBlocks, ChainRouteType, BlockId};
use v1::types::{Block, BlockTransactions, RichBlock, Transaction};

/// Eth PubSub implementation.
pub struct PubSubClient<C> {
	pub client: Arc<C>,
	pub interface: RabbitMqInterface
}

impl<C: BlockChainClient> ChainNotify for PubSubClient<C> {
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
			self.interface.publish(serialized_block, "new_block");
		}
	}
}
