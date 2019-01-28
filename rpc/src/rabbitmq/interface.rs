use v1::{EthClient, Eth};
use ethcore::client::BlockChainClient;
use sync::SyncProvider;
use ethcore::snapshot::SnapshotService;
use ethcore::miner::{self, MinerService};
use miner::external::ExternalMinerService;

// Will use RabbitMQ in the future as transport protocol
/// RabbitMQ interface.
pub struct Interface<C, SN: ?Sized, S: ?Sized, M, EM> where
	C: miner::BlockChainClient + BlockChainClient,
	SN: SnapshotService,
	S: SyncProvider,
	M: MinerService,
	EM: ExternalMinerService,
{
	pub eth_client: EthClient<C, SN, S, M, EM>,
}

impl<C, SN: ?Sized, S: ?Sized, M, EM> Interface<C, SN, S, M, EM> where
	C: miner::BlockChainClient + BlockChainClient,
	SN: SnapshotService,
	S: SyncProvider,
	M: MinerService,
	EM: ExternalMinerService,
	EthClient<C, SN, S, M, EM>: Eth
{

	/// Print new blocks to stdout
	pub fn get_last_block(&self) {
		// TODO
		// Publish new block to RabbitMQ
		let response = &self.eth_client.block_number().unwrap();
		println!("Latest Block --> {:?}", response);
	}
}
