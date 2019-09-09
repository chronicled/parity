use std::sync::Arc;

use ethcore::client::BlockChainClient;
use ethcore::miner::{self, MinerService};
use ethereum_types::H256;
use rlp::Rlp;
use common_types::transaction::{PendingTransaction, SignedTransaction};
use common_types::transaction::Error as TransactionError;
use types::Bytes;

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
	fn send_transaction(&self, payload: Bytes) -> Result<H256, TransactionError>;
}

impl<C: miner::BlockChainClient + BlockChainClient, M: MinerService> Handler for Sender<C, M> {
	fn send_transaction(&self, raw: Bytes) -> Result<H256, TransactionError> {
		let signed_transaction = Rlp::new(&raw.into_vec())
			.as_val()
			.map_err(TransactionError::from)
			.and_then(|tx| SignedTransaction::new(tx).map_err(TransactionError::from))?;
		let pending_transaction: PendingTransaction = signed_transaction.into();
		let hash = pending_transaction.transaction.hash();
		self.miner
			.import_claimed_local_transaction(&*self.client, pending_transaction, false)
			.map(|_| hash)
	}
}
