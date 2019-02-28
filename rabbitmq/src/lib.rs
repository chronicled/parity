extern crate futures;
extern crate lapin_futures as lapin;
extern crate rustc_hex;
extern crate serde;
extern crate serde_json;
extern crate tokio;

#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde_derive;

extern crate ethcore;
extern crate ethcore_miner as miner;
extern crate ethcore_transaction as transaction;
extern crate ethereum_types;
extern crate rlp;

#[cfg(test)]
#[macro_use]
extern crate macros;

pub mod client;
pub mod handler;
pub mod interface;
pub mod tests;
mod types;

const NEW_BLOCK_EXCHANGE_NAME: &'static str = "BlockchainInterface.Output";
const NEW_BLOCK_ROUTING_KEY: &'static str = "interface.in.new-block";
const TOPIC_EXCHANGE: &'static str = "topic";
