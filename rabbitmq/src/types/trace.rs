// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use ethcore::trace::{LocalizedTrace as EthLocalizedTrace, trace, TraceError};
use ethereum_types::{H160, U256};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
// use types::account_diff;
// use types::state_diff;
use vm;

use types::Bytes;


/// Create response
#[derive(Debug, Serialize)]
pub struct Create {
	/// Sender
	from: H160,
	/// Value
	value: U256,
	/// Gas
	gas: U256,
	/// Initialization code
	init: Bytes,
}

impl From<trace::Create> for Create {
	fn from(c: trace::Create) -> Self {
		Create {
			from: c.from,
			value: c.value,
			gas: c.gas,
			init: Bytes::new(c.init),
		}
	}
}

/// Call type.
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CallType {
	/// None
	None,
	/// Call
	Call,
	/// Call code
	CallCode,
	/// Delegate call
	DelegateCall,
	/// Static call
	StaticCall,
}

impl From<vm::CallType> for CallType {
	fn from(c: vm::CallType) -> Self {
		match c {
			vm::CallType::None => CallType::None,
			vm::CallType::Call => CallType::Call,
			vm::CallType::CallCode => CallType::CallCode,
			vm::CallType::DelegateCall => CallType::DelegateCall,
			vm::CallType::StaticCall => CallType::StaticCall,
		}
	}
}

/// Call response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Call {
	/// Sender
	from: H160,
	/// Recipient
	to: H160,
	/// Transfered Value
	value: U256,
	/// Gas
	gas: U256,
	/// Input data
	input: Bytes,
	/// The type of the call.
	call_type: CallType,
}

impl From<trace::Call> for Call {
	fn from(c: trace::Call) -> Self {
		Call {
			from: c.from,
			to: c.to,
			value: c.value,
			gas: c.gas,
			input: c.input.into(),
			call_type: c.call_type.into(),
		}
	}
}

/// Reward type.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RewardType {
	/// Block
	Block,
	/// Uncle
	Uncle,
	/// EmptyStep (AuthorityRound)
	EmptyStep,
	/// External (attributed as part of an external protocol)
	External,
}

impl From<trace::RewardType> for RewardType {
	fn from(c: trace::RewardType) -> Self {
		match c {
			trace::RewardType::Block => RewardType::Block,
			trace::RewardType::Uncle => RewardType::Uncle,
			trace::RewardType::EmptyStep => RewardType::EmptyStep,
			trace::RewardType::External => RewardType::External,
		}
	}
}

/// Reward action
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reward {
	/// Author's address.
	pub author: H160,
	/// Reward amount.
	pub value: U256,
	/// Reward type.
	pub reward_type: RewardType,
}

impl From<trace::Reward> for Reward {
	fn from(r: trace::Reward) -> Self {
		Reward {
			author: r.author,
			value: r.value,
			reward_type: r.reward_type.into(),
		}
	}
}

/// Suicide
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Suicide {
	/// Address.
	pub address: H160,
	/// Refund address.
	pub refund_address: H160,
	/// Balance.
	pub balance: U256,
}

impl From<trace::Suicide> for Suicide {
	fn from(s: trace::Suicide) -> Self {
		Suicide {
			address: s.address,
			refund_address: s.refund_address,
			balance: s.balance,
		}
	}
}

/// Action
#[derive(Debug)]
pub enum Action {
	/// Call
	Call(Call),
	/// Create
	Create(Create),
	/// Suicide
	Suicide(Suicide),
	/// Reward
	Reward(Reward),
}

impl From<trace::Action> for Action {
	fn from(c: trace::Action) -> Self {
		match c {
			trace::Action::Call(call) => Action::Call(call.into()),
			trace::Action::Create(create) => Action::Create(create.into()),
			trace::Action::Suicide(suicide) => Action::Suicide(suicide.into()),
			trace::Action::Reward(reward) => Action::Reward(reward.into()),
		}
	}
}

/// Call Result
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallResult {
	/// Gas used
	gas_used: U256,
	/// Output bytes
	output: Bytes,
}

impl From<trace::CallResult> for CallResult {
	fn from(c: trace::CallResult) -> Self {
		CallResult {
			gas_used: c.gas_used,
			output: c.output.into(),
		}
	}
}

/// Craete Result
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResult {
	/// Gas used
	gas_used: U256,
	/// Code
	code: Bytes,
	/// Assigned address
	address: H160,
}

impl From<trace::CreateResult> for CreateResult {
	fn from(c: trace::CreateResult) -> Self {
		CreateResult {
			gas_used: c.gas_used,
			code: c.code.into(),
			address: c.address,
		}
	}
}

/// Response
#[derive(Debug)]
pub enum Res {
	/// Call
	Call(CallResult),
	/// Create
	Create(CreateResult),
	/// Call failure
	FailedCall(TraceError),
	/// Creation failure
	FailedCreate(TraceError),
	/// None
	None,
}

impl From<trace::Res> for Res {
	fn from(t: trace::Res) -> Self {
		match t {
			trace::Res::Call(call) => Res::Call(CallResult::from(call)),
			trace::Res::Create(create) => Res::Create(CreateResult::from(create)),
			trace::Res::FailedCall(error) => Res::FailedCall(error),
			trace::Res::FailedCreate(error) => Res::FailedCreate(error),
			trace::Res::None => Res::None,
		}
	}
}

/// Trace
#[derive(Debug)]
pub struct Trace {
	/// Trace address
	trace_address: Vec<usize>,
	/// Subtraces
	subtraces: usize,
	/// Action
	action: Action,
	/// Result
	result: Res,
}

impl Serialize for Trace {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where S: Serializer
	{
		let mut struc = serializer.serialize_struct("Trace", 4)?;
		match self.action {
			Action::Call(ref call) => {
				struc.serialize_field("type", "call")?;
				struc.serialize_field("action", call)?;
			},
			Action::Create(ref create) => {
				struc.serialize_field("type", "create")?;
				struc.serialize_field("action", create)?;
			},
			Action::Suicide(ref suicide) => {
				struc.serialize_field("type", "suicide")?;
				struc.serialize_field("action", suicide)?;
			},
			Action::Reward(ref reward) => {
				struc.serialize_field("type", "reward")?;
				struc.serialize_field("action", reward)?;
			},
		}

		match self.result {
			Res::Call(ref call) => struc.serialize_field("result", call)?,
			Res::Create(ref create) => struc.serialize_field("result", create)?,
			Res::FailedCall(ref error) => struc.serialize_field("error", &error.to_string())?,
			Res::FailedCreate(ref error) => struc.serialize_field("error", &error.to_string())?,
			Res::None => struc.serialize_field("result", &None as &Option<u8>)?,
		}

		struc.serialize_field("traceAddress", &self.trace_address)?;
		struc.serialize_field("subtraces", &self.subtraces)?;

		struc.end()
	}
}

impl From<EthLocalizedTrace> for Trace {
	fn from(t: EthLocalizedTrace) -> Self {
		Trace {
			action: t.action.into(),
			result: t.result.into(),
			trace_address: t.trace_address.into_iter().map(Into::into).collect(),
			subtraces: t.subtraces,
		}
	}
}
