use std::sync::Arc;
use txpool::{
  self, Options, LightStatus, Status, Ready, 
  NoopListener, PendingIterator, VerifiedTransaction, Scoring, 
  Error, ErrorKind, Listener
};

use pool::{VerifiedGenericTransaction};
use linked_hash_map::LinkedHashMap;


#[derive(Debug)]
pub struct NoncelessPool<T: VerifiedTransaction> {
	// listener: Arc<L>,
	pub max_count: usize,
	pub max_mem_usage: usize, 
	mem_usage: usize,
  transactions: LinkedHashMap<T::Hash, Arc<T>>,
}

impl<T> NoncelessPool<T> where
  T: VerifiedTransaction + VerifiedGenericTransaction
{
	pub fn new(/*listener: Arc<L>, */max_count: usize, max_mem_usage: usize) -> Self {
		Self {
			// listener,
			max_count,
			max_mem_usage,
			mem_usage: 0,
      transactions: LinkedHashMap::new(),
		}
	}

	pub fn import(&mut self, listener: &mut Listener<T>, transaction: T) -> Result<Arc<T>, Error> {
		let mem_usage = transaction.mem_usage();
		ensure!(!self.transactions.contains_key(transaction.hash()), ErrorKind::AlreadyImported(format!("{:?}", transaction.hash())));

		if self.transactions.len() >= self.max_count || 
				self.mem_usage + mem_usage > self.max_mem_usage 
		{
			let old_hash = self.transactions.back().map_or(String::from("-none-"), |t| format!("{:x}", t.1.hash()));
			let error = ErrorKind::TooCheapToReplace(format!("{:x}", transaction.hash()), old_hash);
			listener.rejected(&transaction.into(), &error);
			bail!(error);
		}

		let shared = Arc::new(transaction);

		self.transactions.insert(shared.hash().clone(), shared.clone());
		listener.added(&shared, None);
		self.mem_usage += shared.mem_usage();

		Ok(shared)
	}

  pub fn clear(&mut self, listener: &mut Listener<T>) {
		for tx in self.transactions.values() {
			listener.dropped(&tx, None)
		}
    self.transactions.clear();
		self.mem_usage = 0;
	}

  pub fn remove(&mut self, listener: &mut Listener<T>, hash: &T::Hash, is_invalid: bool) -> Option<Arc<T>> {
		if let Some(tx) = self.transactions.remove(hash) {
			if is_invalid {
				listener.invalid(&tx);
			} else {
				listener.culled(&tx);
			}
			Some(tx)
		} else {
			None
		}
	}

  pub fn find(&self, hash: &T::Hash) -> Option<Arc<T>> {
		self.transactions.get(hash).map(|t| t.clone())
	}

  pub fn pending(&self) -> linked_hash_map::Values<T::Hash, Arc<T>> {
		self.transactions.values()
	}

  pub fn cull(&mut self, listener: &mut Listener<T>, nonceless_txs: &Vec<T::Hash>) -> usize {
    let mut cnt = 0;
    for hash in nonceless_txs {
      cnt += if self.remove(listener, &hash, false).is_none() {0} else {1};
    }
    cnt
  }

  pub fn light_status(&self) -> LightStatus {    
		LightStatus {
			mem_usage: self.mem_usage,
			transaction_count: self.transactions.len(),
			senders: 0,
		}
	}
}

#[derive(Debug)]
pub struct PoolController<T: VerifiedTransaction + VerifiedGenericTransaction, S: Scoring<T>, L = NoopListener> {
  nonce_pool: txpool::Pool<T, S, L>,
  nonceless_pool: NoncelessPool<T>,
}

impl<T, S, L> PoolController<T, S, L> where
	T: VerifiedTransaction + VerifiedGenericTransaction,
	S: Scoring<T>,
	L: Listener<T>,
{
	/// Creates new `Pool` with given `Scoring`, `Listener` and options.
	pub fn new(listener: L, scoring: S, options: Options) -> Self {
    Self {
      nonce_pool: txpool::Pool::new(listener, scoring, options.clone()),
      nonceless_pool: NoncelessPool::new(options.max_count, options.max_mem_usage)
    }
	}

	pub fn import(&mut self, transaction: T) -> Result<Arc<T>, Error> {
		match transaction.is_nonce_based() {
      true => self.nonce_pool.import(transaction),
      false => self.nonceless_pool.import(self.nonce_pool.listener_mut(), transaction),
    }
	}

	/// Clears pool from all transactions.
	/// This causes a listener notification that all transactions were dropped.
	/// NOTE: the drop-notification order will be arbitrary.
	pub fn clear(&mut self) {
		self.nonce_pool.clear();
    self.nonceless_pool.clear(self.nonce_pool.listener_mut());
	}

	/// Removes single transaction from the pool.
	/// Depending on the `is_invalid` flag the listener
	/// will either get a `cancelled` or `invalid` notification.
	pub fn remove(&mut self, hash: &T::Hash, is_invalid: bool) -> Option<Arc<T>> {
		match self.nonce_pool.remove(hash, is_invalid) {
      None => self.nonceless_pool.remove(self.nonce_pool.listener_mut(), hash, is_invalid),
      r => r,
    }
	}

	/// Removes all stalled transactions from given sender list (or from all senders).
	pub fn cull<R: Ready<T>>(&mut self, senders: Option<&[T::Sender]>, ready: R, nonceless_txs: &Vec<T::Hash>) -> usize {
    self.nonceless_pool.cull(self.nonce_pool.listener_mut(), nonceless_txs) +
		  self.nonce_pool.cull(senders, ready)
	}

	/// Returns a transaction if it's part of the pool or `None` otherwise.
	pub fn find(&self, hash: &T::Hash) -> Option<Arc<T>> {
		match self.nonce_pool.find(hash) {
      None => self.nonceless_pool.find(hash),
      r => r,
    }
	}

	/// Returns worst transaction in the queue (if any).
	pub fn worst_transaction(&self) -> Option<Arc<T>> {
		self.nonce_pool.worst_transaction()
	}

	/// Returns true if the pool is at it's capacity.
	pub fn is_full(&self) -> bool {
		self.nonce_pool.is_full()
	}

	/// Returns senders ordered by priority of their transactions.
	pub fn senders(&self) -> impl Iterator<Item=&T::Sender> {
		self.nonce_pool.senders()
	}

	/// Returns an iterator of pending (ready) transactions.
	pub fn pending<R: Ready<T>>(&self, ready: R) -> PendingMixerIterator<T, txpool::PendingIterator<T, R, S, L>> {
    PendingMixerIterator
    {
      nonce_iterator: self.nonce_pool.pending(ready),
      nonceless_iterator: self.nonceless_pool.pending(),
      next: false,
      permanent: false,
    }
	}

	/// Returns pending (ready) transactions from given sender.
	pub fn pending_from_sender<R: Ready<T>>(&self, ready: R, sender: &T::Sender) -> PendingIterator<T, R, S, L> {
		self.nonce_pool.pending_from_sender(ready, sender)
	}

	/// Returns unprioritized list of ready transactions.
	pub fn unordered_pending<R: Ready<T>>(&self, ready: R) -> PendingMixerIterator<T, txpool::UnorderedIterator<T, R, S>> {
    PendingMixerIterator
    {
      nonce_iterator: self.nonce_pool.unordered_pending(ready),
      nonceless_iterator: self.nonceless_pool.pending(),
      next: false,
      permanent: false,
    }
    // self.nonce_pool.unordered_pending(ready)
    // TODO: add nonceless to the chain
		// self.nonce_pool.unordered_pending(ready)//.chain(self.nonceless_pool.pending().into_iter());
	}

	/// Update score of transactions of a particular sender.
	pub fn update_scores(&mut self, sender: &T::Sender, event: S::Event) {
		self.nonce_pool.update_scores(sender, event);
	}

	/// Computes the full status of the pool (including readiness).
	#[allow(dead_code)]
	pub fn status<R: Ready<T>>(&self, ready: R) -> Status {
		self.nonce_pool.status(ready)
	}

	/// Returns light status of the pool.
	pub fn light_status(&self) -> LightStatus {
    let a = self.nonce_pool.light_status();
    let b = self.nonceless_pool.light_status();
    
		LightStatus {
			mem_usage: a.mem_usage + b.mem_usage,
			transaction_count: a.transaction_count + b.transaction_count,
			senders: a.senders + b.senders,
		}
	}

	/// Returns current pool options.
	pub fn options(&self) -> Options {
		self.nonce_pool.options()
	}

	/// Borrows listener instance.
	pub fn listener(&self) -> &L {
		self.nonce_pool.listener()
	}

	/// Borrows scoring instance.
	pub fn scoring(&self) -> &S {
		self.nonce_pool.scoring()
	}

	/// Borrows listener mutably.
	pub fn listener_mut(&mut self) -> &mut L {
		self.nonce_pool.listener_mut()
	}
}


pub struct PendingMixerIterator<'a, T, I> where
	T: txpool::VerifiedTransaction + 'a,
  I: Iterator<Item = Arc<T>> + 'a
{
  next: bool,
  permanent: bool,
	nonce_iterator: I,
  nonceless_iterator: linked_hash_map::Values<'a, T::Hash, I::Item>,
}

impl<'a, T, I> Iterator for PendingMixerIterator<'a, T, I> where
	T: txpool::VerifiedTransaction,
  I: Iterator<Item = Arc<T>>
{
	type Item = Arc<T>;

	fn next(&mut self) -> Option<Self::Item> {
    let result = match self.next {
      false => self.nonce_iterator.next(),
      true => self.nonceless_iterator.next().map(|t| t.clone())
    };

    if !self.permanent {
      self.next = !self.next;

      if result.is_none() {
        self.permanent = true;
        return self.next();
      }
    }

    result
	}
}