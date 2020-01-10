extern crate boolinator;
extern crate byteorder;
extern crate futures;
extern crate hex;
extern crate hyper;
extern crate kvdb;
extern crate kvdb_rocksdb;
extern crate lapin_futures as lapin;

extern crate rustc_hex;
extern crate serde;
extern crate serde_json;
extern crate tokio;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate prometheus;

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
extern crate parity_runtime;
extern crate rabbitmq_adaptor;
extern crate rlp;
extern crate vm;

#[cfg(test)]
extern crate kvdb_memorydb;
#[cfg(test)]
#[macro_use]
extern crate macros;

pub mod client;
mod common;
pub mod handler;
pub mod tests;
mod types;

const DB_NAME: &'static str = "rabbitmq";
const DEFAULT_CHANNEL_SIZE: usize = 10;
const RETRACTED_CHANNEL_SIZE: usize = 1000;
const START_FROM_INDEX: &[u8] = b"start_from_index";
const DEFAULT_REPLY_QUEUE: &'static str = "BlockchainInterface.default";
const LOG_TARGET: &'static str = "rabbitmq";
const NEW_BLOCK_EXCHANGE_NAME: &'static str = "BlockchainInterface.Output";
const NEW_BLOCK_ROUTING_KEY: &'static str = "interface.in.new-block";
const RETRACTED_BLOCK_ROUTING_KEY: &'static str = "interface.in.retracted-block";
const OPERATION_ID: &'static str = "operation-id";
const PUBLIC_TRANSACTION_QUEUE: &'static str = "BlockchainInterface.public-tx";
const TX_ERROR_EXCHANGE_NAME: &'static str = "BlockchainInterface.TransactionError";
const TX_ERROR_ROUTING_KEY: &'static str = "interface.out.public-tx.error";
