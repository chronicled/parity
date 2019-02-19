use transaction;

/// Represents condition on minimum block number or block timestamp.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TransactionCondition {
	/// Valid at this minimum block number.
	#[serde(rename="block")]
	Number(u64),
	/// Valid at given unix time.
	#[serde(rename="time")]
	Timestamp(u64),
}

impl Into<transaction::Condition> for TransactionCondition {
	fn into(self) -> transaction::Condition {
		match self {
			TransactionCondition::Number(n) => transaction::Condition::Number(n),
			TransactionCondition::Timestamp(n) => transaction::Condition::Timestamp(n),
		}
	}
}

impl From<transaction::Condition> for TransactionCondition {
	fn from(condition: transaction::Condition) -> Self {
		match condition {
			transaction::Condition::Number(n) => TransactionCondition::Number(n),
			transaction::Condition::Timestamp(n) => TransactionCondition::Timestamp(n),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json;

	#[test]
	fn condition_deserialization() {
		let s = r#"[{ "block": 51 }, { "time": 10 }]"#;
		let deserialized: Vec<TransactionCondition> = serde_json::from_str(s).unwrap();
		assert_eq!(deserialized, vec![TransactionCondition::Number(51), TransactionCondition::Timestamp(10)])
	}

	#[test]
	fn condition_into() {
		assert_eq!(transaction::Condition::Number(100), TransactionCondition::Number(100).into());
		assert_eq!(transaction::Condition::Timestamp(100), TransactionCondition::Timestamp(100).into());
	}
}
