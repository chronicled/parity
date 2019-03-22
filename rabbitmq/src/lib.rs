extern crate futures;
extern crate hex;
extern crate lapin_futures as lapin;
extern crate rustc_hex;
extern crate serde;
extern crate serde_json;
extern crate tokio;

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

extern crate common_types;
extern crate enclose;
extern crate ethcore;
extern crate ethcore_miner as miner;
extern crate ethereum_types;
extern crate failure;
extern crate rabbitmq_adaptor;
extern crate rlp;

#[cfg(test)]
#[macro_use]
extern crate macros;

pub mod client;
pub mod handler;
pub mod interface;
pub mod tests;
mod types;

const LOG_TARGET: &'static str = "rabbitmq";
const TRANSACTION_CONSUMER: &'static str = "blockchain-interface";
const NEW_BLOCK_EXCHANGE_NAME: &'static str = "BlockchainInterface.Output";
const NEW_BLOCK_ROUTING_KEY: &'static str = "interface.in.new-block";
const PUBLIC_TRANSACTION_QUEUE: &'static str = "BlockchainInterface.public-tx";
const TOPIC_EXCHANGE: &'static str = "topic";
