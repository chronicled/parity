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

//! Transaction data structure.

use std::ops::Deref;
use ethereum_types::{H256, H512, H160, Address, U256};
use error;
use ethjson;
use ethkey::{self, Signature, Secret, Public, recover, public_to_address};
use evm::Schedule;
use hash::keccak;
use heapsize::HeapSizeOf;
use rlp::{self, RlpStream, Rlp, DecoderError, Encodable};
use crypto::ed25519;

type Bytes = Vec<u8>;
type BlockNumber = u64;

/// Fake address for unsigned transactions as defined by EIP-86.
pub const UNSIGNED_SENDER: Address = H160([0xff; 20]);

/// System sender address for internal state updates.
pub const SYSTEM_ADDRESS: Address = H160([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xfe]);

/// Transaction action type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// Create creates new contract.
	Create,
	/// Calls contract at given address.
	/// In the case of a transfer, this is the receiver's address.'
	Call(Address),
}

impl Default for Action {
	fn default() -> Action { Action::Create }
}

impl rlp::Decodable for Action {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.is_empty() {
			Ok(Action::Create)
		} else {
			Ok(Action::Call(rlp.as_val()?))
		}
	}
}

impl rlp::Encodable for Action {
	fn rlp_append(&self, s: &mut RlpStream) {
		match *self {
			Action::Create => s.append_internal(&""),
			Action::Call(ref addr) => s.append_internal(addr),
		};
	}
}

/// Transaction activation condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
	/// Valid at this block number or later.
	Number(BlockNumber),
	/// Valid at this unix time or later.
	Timestamp(u64),
}

/// Replay protection logic for v part of transaction's signature
pub mod signature {
	/// Adds chain id into v
	pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
		v + if let Some(n) = chain_id { 35 + n * 2 } else { 27 }
	}

	/// Returns refined v
	/// 0 if `v` would have been 27 under "Electrum" notation, 1 if 28 or 4 if invalid.
	pub fn check_replay_protection(v: u64) -> u8 {
		match v {
			v if v == 27 => 0,
			v if v == 28 => 1,
			v if v >= 35 => ((v - 1) % 2) as u8,
			_ => 4
		}
	}
}

/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
	/// Nonce.
	pub nonce: U256,
	/// Gas price.
	pub gas_price: U256,
	/// Gas paid up front for transaction execution.
	pub gas: U256,
	/// Action, can be either call or contract create.
	pub action: Action,
	/// Transfered value.
	pub value: U256,
	/// Transaction data.
	pub data: Bytes,
}

impl Transaction {
	/// Append object with a without signature into RLP stream
	pub fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream, chain_id: Option<u64>) {
		s.begin_list(if chain_id.is_none() { 6 } else { 9 });
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.data);
		if let Some(n) = chain_id {
			s.append(&n);
			s.append(&0u8);
			s.append(&0u8);
		}
	}
}

impl HeapSizeOf for Transaction {
	fn heap_size_of_children(&self) -> usize {
		self.data.heap_size_of_children()
	}
}

impl From<ethjson::state::Transaction> for SignedTransaction {
	fn from(t: ethjson::state::Transaction) -> Self {
		let to: Option<ethjson::hash::Address> = t.to.into();
		let secret = t.secret.map(|s| Secret::from(s.0));
		let tx = Transaction {
			nonce: t.nonce.into(),
			gas_price: t.gas_price.into(),
			gas: t.gas_limit.into(),
			action: match to {
				Some(to) => Action::Call(to.into()),
				None => Action::Create
			},
			value: t.value.into(),
			data: t.data.into(),
		};
		match secret {
			Some(s) => tx.sign(&s, None),
			None => tx.null_sign(1),
		}
	}
}

impl From<ethjson::transaction::Transaction> for UnverifiedTransaction {
	fn from(t: ethjson::transaction::Transaction) -> Self {
		let to: Option<ethjson::hash::Address> = t.to.into();
		UnverifiedTransaction {
			unsigned: Transaction {
				nonce: t.nonce.into(),
				gas_price: t.gas_price.into(),
				gas: t.gas_limit.into(),
				action: match to {
					Some(to) => Action::Call(to.into()),
					None => Action::Create
				},
				value: t.value.into(),
				data: t.data.into(),
			},
			r: t.r.into(),
			s: t.s.into(),
			v: t.v.into(),
			hash: 0.into(),
		}.compute_hash()
	}
}

impl Transaction {
	/// The message hash of the transaction.
	pub fn hash(&self, chain_id: Option<u64>) -> H256 {
		let mut stream = RlpStream::new();
		self.rlp_append_unsigned_transaction(&mut stream, chain_id);
		keccak(stream.as_raw())
	}

	/// Signs the transaction as coming from `sender`.
	pub fn sign(self, secret: &Secret, chain_id: Option<u64>) -> SignedTransaction {
		let sig = ::ethkey::sign(secret, &self.hash(chain_id))
			.expect("data is valid and context has signing capabilities; qed");
		SignedTransaction::new(self.with_signature(sig, chain_id))
			.expect("secret is valid so it's recoverable")
	}

	/// Signs the transaction with signature.
	pub fn with_signature(self, sig: Signature, chain_id: Option<u64>) -> UnverifiedTransaction {
		UnverifiedTransaction {
			unsigned: self,
			r: sig.r().into(),
			s: sig.s().into(),
			v: signature::add_chain_replay_protection(sig.v() as u64, chain_id),
			hash: 0.into(),
		}.compute_hash()
	}

	/// Useful for test incorrectly signed transactions.
	#[cfg(test)]
	pub fn invalid_sign(self) -> UnverifiedTransaction {
		UnverifiedTransaction {
			unsigned: self,
			r: U256::one(),
			s: U256::one(),
			v: 0,
			hash: 0.into(),
		}.compute_hash()
	}

	/// Specify the sender; this won't survive the serialize/deserialize process, but can be cloned.
	pub fn fake_sign(self, from: Address) -> SignedTransaction {
		SignedTransaction {
			transaction: UnverifiedTransaction {
				unsigned: self,
				r: U256::one(),
				s: U256::one(),
				v: 0,
				hash: 0.into(),
			}.compute_hash(),
			sender: from,
			public: None,
		}
	}

	/// Add EIP-86 compatible empty signature.
	pub fn null_sign(self, chain_id: u64) -> SignedTransaction {
		SignedTransaction {
			transaction: UnverifiedTransaction {
				unsigned: self,
				r: U256::zero(),
				s: U256::zero(),
				v: chain_id,
				hash: 0.into(),
			}.compute_hash(),
			sender: UNSIGNED_SENDER,
			public: None,
		}
	}

	/// Get the transaction cost in gas for the given params.
	pub fn gas_required_for(is_create: bool, data: &[u8], schedule: &Schedule) -> u64 {
		data.iter().fold(
			(if is_create {schedule.tx_create_gas} else {schedule.tx_gas}) as u64,
			|g, b| g + (match *b { 0 => schedule.tx_data_zero_gas, _ => schedule.tx_data_non_zero_gas }) as u64
		)
	}

	/// Get the transaction cost in gas for this transaction.
	pub fn gas_required(&self, schedule: &Schedule) -> u64 {
		Self::gas_required_for(match self.action{Action::Create=>true, Action::Call(_)=>false}, &self.data, schedule)
	}
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedTransaction {
	/// Plain Transaction.
	unsigned: Transaction,
	/// The V field of the signature; the LS bit described which half of the curve our point falls
	/// in. The MS bits describe which chain this transaction is for. If 27/28, its for all chains.
	v: u64,
	/// The R field of the signature; helps describe the point on the curve.
	r: U256,
	/// The S field of the signature; helps describe the point on the curve.
	s: U256,
	/// Hash of the transaction
	hash: H256,
}

impl HeapSizeOf for UnverifiedTransaction {
	fn heap_size_of_children(&self) -> usize {
		self.unsigned.heap_size_of_children()
	}
}

impl Deref for UnverifiedTransaction {
	type Target = Transaction;

	fn deref(&self) -> &Self::Target {
		&self.unsigned
	}
}

impl rlp::Decodable for UnverifiedTransaction {
	fn decode(d: &Rlp) -> Result<Self, DecoderError> {
		if d.item_count()? != 9 {
			return Err(DecoderError::RlpIncorrectListLen);
		}
		let hash = keccak(d.as_raw());
		Ok(UnverifiedTransaction {
			unsigned: Transaction {
				nonce: d.val_at(0)?,
				gas_price: d.val_at(1)?,
				gas: d.val_at(2)?,
				action: d.val_at(3)?,
				value: d.val_at(4)?,
				data: d.val_at(5)?,
			},
			v: d.val_at(6)?,
			r: d.val_at(7)?,
			s: d.val_at(8)?,
			hash: hash,
		})
	}
}

impl rlp::Encodable for UnverifiedTransaction {
	fn rlp_append(&self, s: &mut RlpStream) { self.rlp_append_sealed_transaction(s) }
}

pub trait Verifiable {
	fn verify_unordered(&self, chain_id: Option<u64>) -> Result<(), error::Error>;
}

impl UnverifiedTransaction {
	/// Used to compute hash of created transactions
	fn compute_hash(mut self) -> UnverifiedTransaction {
		let hash = keccak(&*self.rlp_bytes());
		self.hash = hash;
		self
	}

	/// Checks is signature is empty.
	pub fn is_unsigned(&self) -> bool {
		self.r.is_zero() && self.s.is_zero()
	}

	pub fn is_typed(&self) -> bool {
		let data = &self.unsigned.data;

		// 3 is a minimum length of RLP of two elements 
		if !&self.is_unsigned() || data.len() < 3 || self.unsigned.nonce.is_zero()  {
			return false
		}
		
		let rlp = Rlp::new(&data);
		rlp.item_count().unwrap_or(0) == 2
	}

	pub fn get_type(&self) -> Result<U256, ethkey::Error> {
		if self.is_typed() {
			Ok(self.nonce)
		} else {
			Err(ethkey::Error::Custom("Has no type, i.e. a regular transaction".to_string()))
		}
	}

	/// Append object with a signature into RLP stream
	fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
		s.begin_list(9);
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.data);
		s.append(&self.v);
		s.append(&self.r);
		s.append(&self.s);
	}

	///	Reference to unsigned part of this transaction.
	pub fn as_unsigned(&self) -> &Transaction {
		&self.unsigned
	}

	pub fn standard_v(&self) -> u8 { signature::check_replay_protection(self.v) }

	/// The `v` value that appears in the RLP.
	pub fn original_v(&self) -> u64 { self.v }

	/// The chain ID, or `None` if this is a global transaction.
	pub fn chain_id(&self) -> Option<u64> {
		match self.v {
			v if self.is_unsigned() => Some(v),
			v if v >= 35 => Some((v - 35) / 2),
			_ => None,
		}
	}

	/// Construct a signature object from the sig.
	pub fn signature(&self) -> Signature {
		Signature::from_rsv(&self.r.into(), &self.s.into(), self.standard_v())
	}

	/// Checks whether the signature has a low 's' value.
	pub fn check_low_s(&self) -> Result<(), ethkey::Error> {
		if !self.signature().is_low_s() {
			Err(ethkey::Error::InvalidSignature.into())
		} else {
			Ok(())
		}
	}

	/// Get the hash of this transaction (keccak of the RLP).
	pub fn hash(&self) -> H256 {
		self.hash
	}

	/// Recovers the public key of the sender.
	pub fn recover_public(&self) -> Result<Public, ethkey::Error> {
		Ok(recover(&self.signature(), &self.unsigned.hash(self.chain_id()))?)
	}

	/// Verify basic signature params. Does not attempt sender recovery.
	pub fn verify_basic(&self, check_low_s: bool, chain_id: Option<u64>, allow_empty_signature: bool, allow_typed_txs: bool) -> Result<(), error::Error> {
		if check_low_s && !(allow_empty_signature && self.is_unsigned()) {
			self.check_low_s()?;
		}
		// Disallow unsigned transactions in case EIP-86 is disabled.
		if !allow_empty_signature && !allow_typed_txs && self.is_unsigned() {
			return Err(ethkey::Error::InvalidSignature.into());
		}
		let pvn_empty = self.gas_price.is_zero() && self.value.is_zero() && self.nonce.is_zero();
		// EIP-86: Transactions of this form MUST have gasprice = 0, nonce = 0, value = 0, and do NOT increment the nonce of account 0.
		if allow_empty_signature && self.is_unsigned() && !allow_typed_txs && !pvn_empty {
			return Err(ethkey::Error::InvalidSignature.into())
		}
		match (self.chain_id(), chain_id) {
			(None, _) => {},
			(Some(n), Some(m)) if n == m => {},
			_ => return Err(error::Error::InvalidChainId),
		};

		if allow_typed_txs && self.is_unsigned() && !pvn_empty {
			UnverifiedTypedTransaction::new(&self)?.verify_basic()?;
		}

		Ok(())
	}
}

impl Verifiable for UnverifiedTransaction {
	/// Additional per-type checks, in verification piplines goes after verify_basic
	fn verify_unordered(&self, chain_id: Option<u64>) -> Result<(), error::Error> {
		// 
		if self.is_typed() {
			UnverifiedTypedTransaction::new(&self)?.verify_unordered(chain_id)?;
		}

		Ok(())
	}
}


/// A transaction with a specific non-regular type, e.g, a ZK origin transaction
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedTypedTransaction {
	/// Plain Transaction.
	unverified: UnverifiedTransaction,
	// Hash of the transaction remains of the same origin

	/// Transaction type to it which corresponds 
	pub tx_type: U256,

	pub typed_payload: Bytes,
	// TODO: do not allow to instantiate tx of non-supported type
}

impl UnverifiedTypedTransaction {
	pub fn new(unverified_tx: &UnverifiedTransaction) -> Result<Self, ethkey::Error> {
		let mut tx = unverified_tx.clone();
		if !&tx.is_typed() {
			return Err(ethkey::Error::Custom("Not a typed tx".to_string()));
		}
		let tx_type = tx.get_type().unwrap();

		if tx_type != U256([2, 0, 0, 0]) {
			return Err(ethkey::Error::Custom("Unsupported type".to_string()));
		}

		let rlp = Rlp::new(&unverified_tx.unsigned.data);
		let data: Bytes = rlp.val_at(0).unwrap();
		let typed_payload: Bytes = rlp.val_at(1).unwrap();
		
		tx.unsigned.data = data;

		Ok(UnverifiedTypedTransaction {
			unverified: tx,
			tx_type: tx_type,
			typed_payload: typed_payload,
		})
	}

	pub fn new_from_bytes(bytes: &[u8]) -> Result<Self, ethkey::Error> {
		let map = |e| {ethkey::Error::Custom(format!("{:?}", e))};
		Self::new(&rlp::decode(&bytes).map_err(map).unwrap())
	}

	pub fn get_type(&self) -> U256 {
		self.tx_type
	}

	pub fn get_typed_tx(&self) -> Result<TypedTransaction, error::Error> {
		match &self.get_type() {
			U256([2, 0, 0, 0]) => Ok(TypedTransaction::ZkOrigin(ZkOriginTransaction::new(&self)?)),
			_ => Err(ethkey::Error::Custom("Invalid type of transaction".to_string()).into())
		}
	}

	/// Verifies if typed transaction is constructable
	pub fn verify_basic(&self) -> Result<(), error::Error> {
		match self.get_typed_tx() {
			Ok(_) => Ok(()),
			Err(e) => Err(e),
		}
	}
}

impl Verifiable for UnverifiedTypedTransaction {
	fn verify_unordered(&self, chain_id: Option<u64>) -> Result<(), error::Error> {
		&self.get_typed_tx()?.get_verifiable()?.verify_unordered(chain_id)?;
		Ok(())
	}
}

// #[derive(Debug, Clone, PartialEq, Eq)]
pub type ProofGroth16 = [u8; 134];

const COINS_IN_CNT: usize = 2;
const COINS_OUT_CNT: usize = 2;

/// Zero-knowledge origin transaction with the corresponding fields
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZkOriginTransaction {
	/// Plain Transaction.
	unverified: UnverifiedTransaction,
	rt: H256,
	sn: [H256; COINS_IN_CNT],
	cm: [H256; COINS_OUT_CNT],
	eph_pk: H256,
	glue: H256,
	k: H256,
	proof: Bytes,
	// Ciphertext
	ct: [Bytes; COINS_OUT_CNT],
	sig:  H512,
}

/// TODO: allow k to be empty, either Option, Enum or Vec
impl ZkOriginTransaction {
	pub fn new(tx: &UnverifiedTypedTransaction) -> Result<Self, DecoderError> {
		// let dtoe = |e| ethkey::Error::Custom(format!("ZKO RLP error {:?}", e));

	 	if tx.get_type() != U256([2, 0, 0, 0]) {
			return Err(DecoderError::Custom("Doesn't match ZKO tx type"))
		}

		if tx.unverified.unsigned.action == Action::Create {
			return Err(DecoderError::Custom("Contract creation isn't supported for ZKO txs"))
		}

		let rlp = Rlp::new(&tx.typed_payload);
		if rlp.item_count().unwrap_or(0) != Self::fields_count() {
			return Err(DecoderError::Custom("Incorrect number of fields for ZkOriginTransaction"))
		}

		let proof_index = 5 + COINS_IN_CNT + COINS_OUT_CNT - 1;
		if rlp.at(proof_index)?.size() != 134 {
			return Err(DecoderError::Custom("Incorrect proof length"));
		}
		
		let unsigned = &tx.unverified.unsigned;
		let v_pub: U256 = unsigned.gas * unsigned.gas_price + unsigned.value;
		if v_pub != U256::from(v_pub.low_u64()) {
			return Err(DecoderError::Custom("v_pub doesn't fit into 64 bits"));
		}

		Ok(ZkOriginTransaction {
			unverified: tx.unverified.clone(),
			rt: rlp.val_at(0)?,
			sn: [rlp.val_at(1)?, rlp.val_at(2)?],
			cm: [rlp.val_at(3)?, rlp.val_at(4)?],
			eph_pk: rlp.val_at(5)?,
			glue: rlp.val_at(6)?,
			k: rlp.val_at(7)?,
			proof: rlp.val_at(8)?,
			ct: [rlp.val_at(9)?, rlp.val_at(10)?],
			sig: rlp.val_at(11)?,
		})
	}

	pub fn new_from_bytes(typed_bytes: &[u8]) -> Result<Self, DecoderError> {
		let unverified_typed = 
			&UnverifiedTypedTransaction::new_from_bytes(&typed_bytes)
			.map_err(|_| {DecoderError::Custom("Cannot instantiate UnverifiedTypedTransaction with typed_bytes")})
			.unwrap();
		Self::new(unverified_typed)
	}

	pub fn fields_count() -> usize {
		6 + COINS_IN_CNT + 2 * COINS_OUT_CNT
	}

	pub fn get_v_pub(&self) -> u64 {
		let tx = &self.unverified.unsigned;
		(tx.gas_price * tx.gas + tx.value).as_u64()
	}

	pub fn rlp_append_unsigned_tz(&self, s: &mut RlpStream) {
		s.begin_list(Self::fields_count() - 1);
		s.append(&self.rt);
		for sn in &self.sn { s.append(sn); }
		for cm in &self.cm { s.append(cm); }
		s.append(&self.eph_pk);
		s.append(&self.glue);
		s.append(&self.k);
		s.append(&self.proof);
		for ct in &self.ct { s.append(ct); }
	}

	pub fn get_unsigned_msg(&self, _chain_id: Option<u64>) -> Bytes {
		let mut zs = RlpStream::new();
		self.rlp_append_unsigned_tz(&mut zs);
		
		let z: &Bytes = &zs.out();
		let call_data = &self.unverified.unsigned.data;
		// Consider using out()
		let d_prime: Bytes = RlpStream::new().begin_list(2).append(call_data).append(z).as_raw().to_vec();

		let mut unverified = self.unverified.clone();
		unverified.unsigned.data = d_prime;
		rlp::encode(&unverified)

		// let chain_id_ensured = Some(chain_id.unwrap_or(0u64));
		// let mut unsigned_stream = RlpStream::new();
		// tx.rlp_append_unsigned_transaction(&mut unsigned_stream, chain_id_ensured);
		// rlp_append_sealed_transaction
		// unsigned_stream.out()
	}

	pub fn verify_signature(&self, chain_id: Option<u64>) -> bool {
		ed25519::verify(&self.get_unsigned_msg(chain_id), &self.eph_pk as &[u8], &self.sig as &[u8])
	}

	pub fn sign(&self, sk: &[u8]) -> [u8; 64] {
		ed25519::signature(&self.get_unsigned_msg(None), &sk)
	}
}

impl HeapSizeOf for ZkOriginTransaction {
	fn heap_size_of_children(&self) -> usize {
		self.unverified.heap_size_of_children() +
		self.proof.heap_size_of_children() +
		self.ct.iter().fold(0, |acc, b| acc + b.heap_size_of_children())
	}
}

impl Verifiable for ZkOriginTransaction {
	fn verify_unordered(&self, chain_id: Option<u64>) -> Result<(), error::Error> {
		if !&self.verify_signature(chain_id) {
			return Err(ethkey::Error::Custom("ZKO signature is incorrect".into()).into())
		}

		Ok(())
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TypedTransaction {
	ZkOrigin(ZkOriginTransaction),
}

impl TypedTransaction {
	pub fn get_verifiable(&self) -> Result<&impl Verifiable, error::Error> {
		match &self {
			TypedTransaction::ZkOrigin(ref tx) => Ok(tx),
			// No need for default, compliler's check is exhaustve
			// _ => Err(ethkey::Error::Custom(format!("No verifiable for {:?}", &self)).into()),
		}
	}
}

/// A `UnverifiedTransaction` with successfully recovered `sender`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignedTransaction {
	transaction: UnverifiedTransaction,
	sender: Address,
	public: Option<Public>,
}

impl HeapSizeOf for SignedTransaction {
	fn heap_size_of_children(&self) -> usize {
		self.transaction.heap_size_of_children()
	}
}

impl rlp::Encodable for SignedTransaction {
	fn rlp_append(&self, s: &mut RlpStream) { self.transaction.rlp_append_sealed_transaction(s) }
}

impl Deref for SignedTransaction {
	type Target = UnverifiedTransaction;
	fn deref(&self) -> &Self::Target {
		&self.transaction
	}
}

impl From<SignedTransaction> for UnverifiedTransaction {
	fn from(tx: SignedTransaction) -> Self {
		tx.transaction
	}
}

impl SignedTransaction {
	/// Try to verify transaction and recover sender.
	pub fn new(transaction: UnverifiedTransaction) -> Result<Self, ethkey::Error> {
		if transaction.is_unsigned() {
			// TODO: move out of here and get proper chain_id
			transaction.verify_unordered(Some(0)).map_err(|e| {ethkey::Error::Custom(format!("{:?}", e))})?;
			Ok(SignedTransaction {
				transaction: transaction,
				sender: UNSIGNED_SENDER,
				public: None,
			})
		} else {
			let public = transaction.recover_public()?;
			let sender = public_to_address(&public);
			Ok(SignedTransaction {
				transaction: transaction,
				sender: sender,
				public: Some(public),
			})
		}
	}

	/// Returns transaction sender.
	pub fn sender(&self) -> Address {
		self.sender
	}

	/// Returns a public key of the sender.
	pub fn public_key(&self) -> Option<Public> {
		self.public
	}

	/// Checks is signature is empty.
	pub fn is_unsigned(&self) -> bool {
		self.transaction.is_unsigned()
	}

	/// Deconstructs this transaction back into `UnverifiedTransaction`
	pub fn deconstruct(self) -> (UnverifiedTransaction, Address, Option<Public>) {
		(self.transaction, self.sender, self.public)
	}
}

/// Signed Transaction that is a part of canon blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedTransaction {
	/// Signed part.
	pub signed: UnverifiedTransaction,
	/// Block number.
	pub block_number: BlockNumber,
	/// Block hash.
	pub block_hash: H256,
	/// Transaction index within block.
	pub transaction_index: usize,
	/// Cached sender
	pub cached_sender: Option<Address>,
}

impl LocalizedTransaction {
	/// Returns transaction sender.
	/// Panics if `LocalizedTransaction` is constructed using invalid `UnverifiedTransaction`.
	pub fn sender(&mut self) -> Address {
		if let Some(sender) = self.cached_sender {
			return sender;
		}
		if self.is_unsigned() {
			return UNSIGNED_SENDER.clone();
		}
		let sender = public_to_address(&self.recover_public()
			.expect("LocalizedTransaction is always constructed from transaction from blockchain; Blockchain only stores verified transactions; qed"));
		self.cached_sender = Some(sender);
		sender
	}
}

impl Deref for LocalizedTransaction {
	type Target = UnverifiedTransaction;

	fn deref(&self) -> &Self::Target {
		&self.signed
	}
}

/// Queued transaction with additional information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransaction {
	/// Signed transaction data.
	pub transaction: SignedTransaction,
	/// To be activated at this condition. `None` for immediately.
	pub condition: Option<Condition>,
}

impl PendingTransaction {
	/// Create a new pending transaction from signed transaction.
	pub fn new(signed: SignedTransaction, condition: Option<Condition>) -> Self {
		PendingTransaction {
			transaction: signed,
			condition: condition,
		}
	}

	/// Checks is signature is empty.
	pub fn is_unsigned(&self) -> bool {
		self.transaction.is_unsigned()
	}
}

impl Deref for PendingTransaction {
	type Target = SignedTransaction;

	fn deref(&self) -> &SignedTransaction { &self.transaction }
}

impl From<SignedTransaction> for PendingTransaction {
	fn from(t: SignedTransaction) -> Self {
		PendingTransaction {
			transaction: t,
			condition: None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ethereum_types::U256;
	use hash::keccak;

	#[test]
	fn sender_test() {
		let bytes = ::rustc_hex::FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
		let t: UnverifiedTransaction = rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
		assert_eq!(t.data, b"");
		assert_eq!(t.gas, U256::from(0x5208u64));
		assert_eq!(t.gas_price, U256::from(0x01u64));
		assert_eq!(t.nonce, U256::from(0x00u64));
		if let Action::Call(ref to) = t.action {
			assert_eq!(*to, "095e7baea6a6c7c4c2dfeb977efac326af552d87".into());
		} else { panic!(); }
		assert_eq!(t.value, U256::from(0x0au64));
		assert_eq!(public_to_address(&t.recover_public().unwrap()), "0f65fe9276bc9a24ae7083ae28e2660ef72df99e".into());
		assert_eq!(t.chain_id(), None);
	}

	#[test]
	fn signing_eip155_zero_chainid() {
		use ethkey::{Random, Generator};

		let key = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec()
		};

		let hash = t.hash(Some(0));
		let sig = ::ethkey::sign(&key.secret(), &hash).unwrap();
		let u = t.with_signature(sig, Some(0));

		assert!(SignedTransaction::new(u).is_ok());
	}

	#[test]
	fn signing() {
		use ethkey::{Random, Generator};

		let key = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec()
		}.sign(&key.secret(), None);
		assert_eq!(Address::from(keccak(key.public())), t.sender());
		assert_eq!(t.chain_id(), None);
	}

	#[test]
	fn fake_signing() {
		let t = Transaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec()
		}.fake_sign(Address::from(0x69));
		assert_eq!(Address::from(0x69), t.sender());
		assert_eq!(t.chain_id(), None);

		let t = t.clone();
		assert_eq!(Address::from(0x69), t.sender());
		assert_eq!(t.chain_id(), None);
	}

	#[test]
	fn should_recover_from_chain_specific_signing() {
		use ethkey::{Random, Generator};
		let key = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec()
		}.sign(&key.secret(), Some(69));
		assert_eq!(Address::from(keccak(key.public())), t.sender());
		assert_eq!(t.chain_id(), Some(69));
	}

	#[test]
	fn should_agree_with_vitalik() {
		use rustc_hex::FromHex;

		let test_vector = |tx_data: &str, address: &'static str| {
			let signed = rlp::decode(&FromHex::from_hex(tx_data).unwrap()).expect("decoding tx data failed");
			let signed = SignedTransaction::new(signed).unwrap();
			assert_eq!(signed.sender(), address.into());
			println!("chainid: {:?}", signed.chain_id());
		};

		test_vector("f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d", "0xf0f6f18bca1b28cd68e4357452947e021241e9ce");
		test_vector("f864018504a817c80182a410943535353535353535353535353535353535353535018025a0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bcaa0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6", "0x23ef145a395ea3fa3deb533b8a9e1b4c6c25d112");
		test_vector("f864028504a817c80282f618943535353535353535353535353535353535353535088025a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5", "0x2e485e0c23b4c3c542628a5f672eeab0ad4888be");
		test_vector("f865038504a817c803830148209435353535353535353535353535353535353535351b8025a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4e0a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de", "0x82a88539669a3fd524d669e858935de5e5410cf0");
		test_vector("f865048504a817c80483019a28943535353535353535353535353535353535353535408025a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c063a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060", "0xf9358f2538fd5ccfeb848b64a96b743fcc930554");
		test_vector("f865058504a817c8058301ec309435353535353535353535353535353535353535357d8025a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1", "0xa8f7aba377317440bc5b26198a363ad22af1f3a4");
		test_vector("f866068504a817c80683023e3894353535353535353535353535353535353535353581d88025a06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2fa06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d", "0xf1f571dc362a0e5b2696b8e775f8491d3e50de35");
		test_vector("f867078504a817c807830290409435353535353535353535353535353535353535358201578025a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021", "0xd37922162ab7cea97c97a87551ed02c9a38b7332");
		test_vector("f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10", "0x9bddad43f934d313c2b79ca28a432dd2b7281029");
		test_vector("f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb", "0x3c24d7329e92f84f08556ceb6df1cdb0104ca49f");
	}

	#[test]
	fn should_recognize_typed_tx() {
		use rustc_hex::FromHex;

		let untyped = FromHex::from_hex("f863800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a84aabbccdd1ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
		let t1: UnverifiedTransaction = rlp::decode(&untyped).expect("decoding UnverifiedTransaction failed");
		assert_eq!(t1.is_typed(), false);

		let typed = FromHex::from_hex("ea020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a8bca841100110084aabbccdd1b8080").unwrap();
		let t2: UnverifiedTransaction = rlp::decode(&typed).expect("decoding UnverifiedTransaction failed");
		assert_eq!(t2.is_typed(), true);
		assert_eq!(t2.get_type().unwrap(), U256([2, 0, 0, 0]));

		let t2_typed = UnverifiedTypedTransaction::new(&t2).unwrap();
		assert_eq!(&t2_typed.unverified.unsigned.data, &FromHex::from_hex("11001100").unwrap());
		assert_eq!(&t2_typed.typed_payload, &FromHex::from_hex("aabbccdd").unwrap());
	}

	#[test]
	fn should_parse_zko_tx() {
		use rustc_hex::FromHex;

		let typed_bytes = FromHex::from_hex("f902b2020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab90291f9028e84aabbccddb90286f90283a03a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3a0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802a0826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8fa0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12b8407af1bd981c4b64df73aaa33846a1a2f09a3012ca082d3559c220481fd71c7e0e04b986cf7737bf43c5c2cdaf88f74025d58a2872db448f8c0303184186c4287ba03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4db84023d0c12636b3444530ae2d3b5cc8b60be5ec042ba7ee8781b72aa21ba65785ad5d52b65bd2c8997bb255f895531e3483194ed5f88088058c36479eee5f0ab2721b8080").unwrap();
		let tx: UnverifiedTransaction = rlp::decode(&typed_bytes).expect("decoding UnverifiedTransaction failed");
		let zko_tx = ZkOriginTransaction::new(&UnverifiedTypedTransaction::new(&tx).unwrap()).unwrap();
		
		assert_eq!(zko_tx.get_v_pub(), 21_010u64);
		assert_eq!(zko_tx.unverified.unsigned.data, FromHex::from_hex("aabbccdd").unwrap());
		assert_eq!(format!("{:?}", zko_tx.unverified.hash), "0x6bb6591c73996ade7cfc34fb11400b7a449bfa3aadf8ec85365cbb834ec86fa8");
		assert_eq!(format!("{:?}", zko_tx.rt), "0x3a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3");
		assert_eq!(format!("{:?}", zko_tx.sn[0]), "0xca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352");
		assert_eq!(format!("{:?}", zko_tx.sn[1]), "0x2018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802");
		assert_eq!(format!("{:?}", zko_tx.cm[0]), "0x826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8f");
		assert_eq!(format!("{:?}", zko_tx.cm[1]), "0xdfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12");
		assert_eq!(format!("{:?}", zko_tx.eph_pk), "0x7af1bd981c4b64df73aaa33846a1a2f09a3012ca082d3559c220481fd71c7e0e04b986cf7737bf43c5c2cdaf88f74025d58a2872db448f8c0303184186c4287b");
		assert_eq!(format!("{:?}", zko_tx.glue), "0x3f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436e");
		assert_eq!(format!("{:?}", zko_tx.k), "0xbe3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2");
		assert_eq!(zko_tx.proof, FromHex::from_hex("683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedba").unwrap());
		assert_eq!(zko_tx.ct[0], FromHex::from_hex("38d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8").unwrap());
		assert_eq!(zko_tx.ct[1], FromHex::from_hex("59d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4d").unwrap());
		assert_eq!(format!("{:?}", zko_tx.sig), "0x23d0c12636b3444530ae2d3b5cc8b60be5ec042ba7ee8781b72aa21ba65785ad5d52b65bd2c8997bb255f895531e3483194ed5f88088058c36479eee5f0ab272");
	}

	#[test]
	fn should_not_parse_zko_tx() {
		use rustc_hex::FromHex;

		let typed_invalid = FromHex::from_hex("ea020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a8bca841100110084aabbccdd1b8080").unwrap();
		let tx_ivalid: UnverifiedTransaction = rlp::decode(&typed_invalid).expect("decoding UnverifiedTransaction failed");
		let zko_tx_invalid = ZkOriginTransaction::new(&UnverifiedTypedTransaction::new(&tx_ivalid).unwrap()).ok();
		assert_eq!(zko_tx_invalid, None);
		
		let hex_zk_opt = |h: &[u8]| {
			ZkOriginTransaction::new(
				&UnverifiedTypedTransaction::new(
					&rlp::decode(&h).unwrap()
				).unwrap()
			).ok()
		};

		vec![
			"ea020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a8bca841100110084aabbccdd1b8080",
			"f902b1020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab90290f9028d84aabbccddb90285f90282a03a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3a0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a8029f826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23dea0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12b8407af1bd981c4b64df73aaa33846a1a2f09a3012ca082d3559c220481fd71c7e0e04b986cf7737bf43c5c2cdaf88f74025d58a2872db448f8c0303184186c4287ba03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4db84023d0c12636b3444530ae2d3b5cc8b60be5ec042ba7ee8781b72aa21ba65785ad5d52b65bd2c8997bb255f895531e3483194ed5f88088058c36479eee5f0ab2721b8080",
			"f902b1020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab90290f9028d84aabbccddb90285f902829f3a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fa0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802a0826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8fa0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12b8407af1bd981c4b64df73aaa33846a1a2f09a3012ca082d3559c220481fd71c7e0e04b986cf7737bf43c5c2cdaf88f74025d58a2872db448f8c0303184186c4287ba03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4db84023d0c12636b3444530ae2d3b5cc8b60be5ec042ba7ee8781b72aa21ba65785ad5d52b65bd2c8997bb255f895531e3483194ed5f88088058c36479eee5f0ab2721b8080",
			"f902a1020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab90280f9027d84aabbccddb90275f90272a03a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3a0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802a0826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8fa0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12b8407af1bd981c4b64df73aaa33846a1a2f09a3012ca082d3559c220481fd71c7e0e04b986cf7737bf43c5c2cdaf88f74025d58a2872db448f8c0303184186c4287ba03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4db023d0c12636b3444530ae2d3b5cc8b60be5ec042ba7ee8781b72aa21ba65785ad5d52b65bd2c8997bb255f895531e34801b8080",
		].into_iter()
		.map(|hex| FromHex::from_hex(hex).unwrap())
		.for_each(|hex| assert_eq!(hex_zk_opt(&hex), None));
	}

	#[test]
	fn unsigned_zko_tx_should_be_valid() {
		use rustc_hex::FromHex;
		let chain_id = None;

		let signed = FromHex::from_hex("f902b2020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab90291f9028e84aabbccddb90286f90283a03a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3a0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802a0826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8fa0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12b8407af1bd981c4b64df73aaa33846a1a2f09a3012ca082d3559c220481fd71c7e0e04b986cf7737bf43c5c2cdaf88f74025d58a2872db448f8c0303184186c4287ba03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4db84023d0c12636b3444530ae2d3b5cc8b60be5ec042ba7ee8781b72aa21ba65785ad5d52b65bd2c8997bb255f895531e3483194ed5f88088058c36479eee5f0ab2721b8080").unwrap();
		let unsigned = FromHex::from_hex("f90270020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab9024ff9024c84aabbccddb90244f90241a03a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3a0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802a0826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8fa0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12b8407af1bd981c4b64df73aaa33846a1a2f09a3012ca082d3559c220481fd71c7e0e04b986cf7737bf43c5c2cdaf88f74025d58a2872db448f8c0303184186c4287ba03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4d808080").unwrap();
		let zko_tx = ZkOriginTransaction::new_from_bytes(&signed).unwrap();
		assert_eq!(zko_tx.get_unsigned_msg(chain_id), unsigned);
		assert_eq!(zko_tx.verify_unordered(chain_id).is_err(), true);
	}

	#[test]
	fn should_verify_signed() {
		use rustc_hex::FromHex;
		let chain_id = None;

		// sk = seed || pub_key
		// sk 6f88a747b5956074ed8d5364bb4fbba9b7319986b07642cc8127fa82d9ba229d379f8f2594df7d4a09481615e27c869dcc68e5819330dfccaeb87733e1c19f96
		// pk 379f8f2594df7d4a09481615e27c869dcc68e5819330dfccaeb87733e1c19f96
		// msg f9024f020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab9022ef9022b84aabbccddb90223f90220a03a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3a0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802a0826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8fa0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12a0379f8f2594df7d4a09481615e27c869dcc68e5819330dfccaeb87733e1c19f96a03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4d808080
		// sig b8e768655fd075c064809348bd759a9cbc5055eafd1860e9498ca8ab2a373b888de62f48fbb1b0864e9b11ca5c5c882db2310ae80a1e27cc099c7ce6e778de0d
		// let seed = FromHex::from_hex("6f88a747b5956074ed8d5364bb4fbba9b7319986b07642cc8127fa82d9ba229d").unwrap();
		// let keypair = ed25519::keypair(&seed);


		// Correct sig for the transaction:
		let signed = FromHex::from_hex("f90291020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab90270f9026d84aabbccddb90265f90262a03a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3a0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802a0826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8fa0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12a0379f8f2594df7d4a09481615e27c869dcc68e5819330dfccaeb87733e1c19f96a03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4db840b8e768655fd075c064809348bd759a9cbc5055eafd1860e9498ca8ab2a373b888de62f48fbb1b0864e9b11ca5c5c882db2310ae80a1e27cc099c7ce6e778de0d808080").unwrap();
		let zko_tx = ZkOriginTransaction::new_from_bytes(&signed).unwrap();
		assert_eq!(zko_tx.verify_unordered(chain_id).is_ok(), true);
		

		// Incorrect chain_id, signed 0, provided 27 in tx
		let signed_incorrect_chain_id = FromHex::from_hex("f90291020182520894095e7baea6a6c7c4c2dfeb977efac326af552d870ab90270f9026d84aabbccddb90265f90262a03a6fc31fbd331deb703849999592c8ea6a7bb9fb3a7f0c7e948a9bc97d4d7fd3a0ca20d232804cfac1dd676951803bbda9fede314cc2d913cb616ce144eb032352a02018b9d628f92be176992bb761021c8750fed0a43dca3ec2c82f3ac95762a802a0826e8170ceee7675414ec9945be697c1719a5d3fc5a66591d427cb1b8a23de8fa0dfd10dd0ab1342304bd8a85a40ca376aece5fc74ea77031866d78e893df71b12a0379f8f2594df7d4a09481615e27c869dcc68e5819330dfccaeb87733e1c19f96a03f7a942c28c8d497c7575989efe7a809b9950eada377a83d1a86cb7bff7e436ea0be3db515a9572200a8f4e377df1137fa5b5ad0b3962c581a4551848fcc7b51a2b886683ee16c40833d5bf2550b660d5d9eb772840030a59253722e954d9cb56c5c806a75e44924e26c528ae587bfbcfdaa7c73b004ce5d4779c1fcda7e009eca43cd8fcf471b40b10cc6dac5da75ee6e698022ed90a6a3e9fc028a5bdcac17a22dd4eaa35b320a20d1c42d19bc348ca2eb93d5dd4becf291715f27d0b8bc90b9f142f2f2fa9eedbab84638d04eae18760f7b111c258de48737eb86593df858e7e61c640191a1bcbeb6b1595b441156e3a672f0f4e5f86bb065ddb39060e2d61dbee7b21663d58c8d03c9c5285836e5e8b84659d4a0377662c152b24b9ac86c764eead180e1db217a52935f6f823abc6337709513a48f63b5a5957d9057b0b5a597b4e83b67cff1e149887cd23fa17e00b2b205c673466d4db840b8e768655fd075c064809348bd759a9cbc5055eafd1860e9498ca8ab2a373b888de62f48fbb1b0864e9b11ca5c5c882db2310ae80a1e27cc099c7ce6e778de0d1b8080").unwrap();
		let zko_tx_incorrect_chain_id = ZkOriginTransaction::new_from_bytes(&signed_incorrect_chain_id).unwrap();
		assert_eq!(zko_tx_incorrect_chain_id.verify_unordered(chain_id).is_ok(), false);
	}
}
