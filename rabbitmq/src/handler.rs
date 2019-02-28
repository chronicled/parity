use failure::Error;
use std::sync::Arc;

use ethcore::client::BlockChainClient;
use ethcore::miner::{self, MinerService};
use ethereum_types::H256;
use rlp::Rlp;
use transaction::{PendingTransaction, SignedTransaction};

/// A Sender which uses references to a client and miner in order to send transactions
#[derive(Debug)]
pub struct Sender<C, M> {
	client: Arc<C>,
	miner: Arc<M>,
}

impl<C, M> Sender<C, M> {
	/// Create a `Sender` from Arc references to a client and miner.
	pub fn new(client: Arc<C>, miner: Arc<M>) -> Self {
		Sender { client, miner }
	}
}

pub trait Handler: Sync + Send {
	fn send_transaction(&self, id: String, payload: &Vec<u8>) -> Result<H256, Error>;
}

impl<C: miner::BlockChainClient + BlockChainClient, M: MinerService> Handler for Sender<C, M> {
	fn send_transaction(&self, id: String, payload: &Vec<u8>) -> Result<H256, Error> {
		let signed_transaction = Rlp::new(&payload)
			.as_val()
			.map_err(Error::from)
			.and_then(|tx| SignedTransaction::new(tx).map_err(Error::from))?;

		let pending_transaction: PendingTransaction = signed_transaction.into();
		let hash = pending_transaction.transaction.hash();
		self.miner
			.import_claimed_local_transaction(&*self.client, pending_transaction, false)
			.map_err(Error::from)
			.map(|_| hash)
	}
}
