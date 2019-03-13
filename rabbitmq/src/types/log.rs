use types::{Bytes, H160, H256};
use common_types::log_entry::LocalizedLogEntry;

/// Log representation
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
	/// Hash of the transaction that triggered this log
	pub transaction_hash: H256,
	/// Index of the log in the transaction
	pub transaction_log_index: usize,
	/// Sender of the transaction
	pub address: H160,
	/// Data of the log
	pub data: Bytes,
	/// Topics of the log
	pub topics: Vec<H256>,
}

impl From<LocalizedLogEntry> for Log {
	fn from(h: LocalizedLogEntry) -> Self {
		Log {
			transaction_hash: h.transaction_hash.into(),
			transaction_log_index: h.transaction_log_index,
			address: h.entry.address.into(),
			data: h.entry.data.into(),
			topics: h.entry.topics.into_iter().map(Into::into).collect(),
		}
	}
}
