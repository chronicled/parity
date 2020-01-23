use futures::Stream;
use futures::{Future, IntoFuture};
use futures::future::{ok, lazy};
use kvdb_memorydb;
use kvdb::{DBTransaction, KeyValueDB};
use tokio::sync::mpsc::channel;
use std::sync::Arc;
use byteorder::{LittleEndian, ByteOrder};
use enclose::enclose;

use std::time::Duration;

use START_FROM_INDEX;
use client::PubSubClient;
use client::construct_new_block;
use ethcore::client::{
	ChainNotify, ChainRoute, ChainRouteType, EachBlockWith, NewBlocks, TestBlockChainClient,
};

const DURATION_ZERO: Duration = Duration::from_millis(0);

#[test]
fn should_subscribe_to_new_blocks() {
	let mut client = TestBlockChainClient::new();
	// Insert some blocks
	client.add_blocks(4, EachBlockWith::Nothing);
	let h4 = client.block_hash_delta_minus(1);
	let h3 = client.block_hash_delta_minus(2);
	let h2 = client.block_hash_delta_minus(3);
	let h1 = client.block_hash_delta_minus(4);

	// Create a sync_channel with buffer size 3
	let (sender, receiver) = channel::<u64>(4);
	let dummy_rabbitmq_client = PubSubClient {
		blockchain_client: Arc::new(client),
		sender: sender,
		database: Arc::new(kvdb_memorydb::create(0)),
	};

	// Check notifications
	// Notify about 3 blocks
	dummy_rabbitmq_client.new_blocks(NewBlocks::new(
		vec![],
		vec![],
		ChainRoute::new(vec![
			(h1, ChainRouteType::Enacted),
			(h2, ChainRouteType::Retracted),
			(h3, ChainRouteType::Enacted),
			(h4, ChainRouteType::Enacted),
		]),
		vec![],
		vec![],
		DURATION_ZERO,
		true,
	));
	let mut block_receiver = receiver.wait();

	let new_block = block_receiver.next().unwrap().unwrap();
	assert_eq!(new_block, 1);

	let new_block = block_receiver.next().unwrap().unwrap();
	assert_eq!(new_block, 3);

	let new_block = block_receiver.next().unwrap().unwrap();
	assert_eq!(new_block, 4);
}

// [jl/CHRON-10880]
// Test for checking that genesis block is emitted.
// Note that before this implementation, there were few things preventing the genesis block from being emitted.
// 1. START_FROM_INDEX was incremented before the block was produced, not after.
// 	- This meant that, even though START_FROM_INDEX started at 0, receiver logic would increment it to 1 before constructing and producing the block, thereby skipping the genesis block
// 2. construct_new_block() returned Err when the block receipts and extra_info fields were missing from the block, which the gensis block was missing.
// Therefore, fixing these issues, we can see that genesis block is indeed successfully created in this simple unit test. Previous code did not pass this test.
#[test]
fn should_receive_genesis_block() {
	let mut client = TestBlockChainClient::new();
	let mut db = Arc::new(kvdb_memorydb::create(0));
	// Insert 4 blocks, meaning there will be 5 blocks including the genesis block.
	client.add_blocks(4, EachBlockWith::Nothing);

	// get hashes of all the blocks.
	let h4 = client.block_hash_delta_minus(1);
	let h3 = client.block_hash_delta_minus(2);
	let h2 = client.block_hash_delta_minus(3);
	let h1 = client.block_hash_delta_minus(4);
	// genesis block hash
	let h0 = client.block_hash_delta_minus(5);

	// wrap client in arc
	let mut client = Arc::new(client);

	// Create a sync_channel with buffer size 5
	let (sender, receiver) = channel::<u64>(5);
	let dummy_rabbitmq_client = PubSubClient {
		blockchain_client: client.clone(),
		sender: sender,
		database: db.clone(),
	};

	// Check notifications
	// Notify all 5 blocks including the genesis block
	dummy_rabbitmq_client.new_blocks(NewBlocks::new(
		vec![],
		vec![],
		ChainRoute::new(vec![
			(h0, ChainRouteType::Enacted),
			(h1, ChainRouteType::Enacted),
			(h2, ChainRouteType::Enacted),
			(h3, ChainRouteType::Enacted),
			(h4, ChainRouteType::Enacted),
		]),
		vec![],
		vec![],
		DURATION_ZERO,
		true,
	));

	// This is the database part of the produce_new_block() function in ./rabbitmq/src/client.rs
	let produce_new_block = |db: Arc<kvdb_memorydb::InMemory>, block: _, block_number: u64| {
		let mut transaction = DBTransaction::new();
		transaction.put(None, START_FROM_INDEX, &(block_number + 1).to_le_bytes());
		db.clone().write(transaction).map_err(|_| ());
		Ok(block)
	};

	// This is the receiver_logic in ./rabbitmq/src/client.rs
	// It first checks the START_FROM_INDEX value, then,
	// constructs and produces new block
	let receiver_logic = enclose!((db) move |block_number| {
		let mut start_from_index: u64 = db.get(None, START_FROM_INDEX)
			.expect("low-level database error")
			.and_then(|val| {
				Some(LittleEndian::read_u64(&val[..]))
			})
			.unwrap_or(0u64);

		start_from_index = if start_from_index >= block_number { block_number } else { start_from_index };

		if let Some(serialized_block) = construct_new_block(start_from_index, client.clone()) {
			produce_new_block(db.clone(), serialized_block, start_from_index)
		} else {
			Err(())
		}
	});

	// Collect all values in stream as an iterator
	let mut block_iter = receiver.map_err(|_| ()).wait();

	// Get the START_FROM_INDEX value before producing block; it should be 0.
	let mut start_from_index: u64 = db.get(None, START_FROM_INDEX)
				.expect("low-level database error")
				.and_then(|val| {
					Some(LittleEndian::read_u64(&val[..]))
				})
				.unwrap_or(0u64);
	assert_eq!(start_from_index, 0);

	// Get the hash value received from the receiver.
	let hash0 = block_iter.next().unwrap().unwrap();
	// Check that the first hash_value received from the receiver is 0
	assert_eq!(hash0, 0);

	// With the given value, carry out the receiver logic, then check that the block produced as the genesis block is correct.
	let block0 = receiver_logic(hash0).unwrap();
	assert_eq!(block0, r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x20000","extraData":"0x","gasLimit":"0x2fefd8","gasUsed":"0x0","hash":"0x0cd786a2425d16f152c658316c423e6ce1181e15c3295826d7c9904cba9ce303","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","number":"0x0","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","sealFields":["0xa000000000000000000000000000000000000000647572616c65787365646c6578","0x8800006d6f7264656e"],"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x1fb","stateRoot":"0xf3f4696bbf3b3b07775128eb7a3763279a394e382130f27c21e70233e04946a9","timestamp":"0x0","totalDifficulty":null,"transactions":[],"transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","uncles":[]}"#);

	// Get START_FROM_INDEX after producing genesis block to see that it incremented.
	start_from_index = db.get(None, START_FROM_INDEX)
				.expect("low-level database error")
				.and_then(|val| {
					Some(LittleEndian::read_u64(&val[..]))
				})
				.unwrap_or(0u64);
	// Check that it's the second block
	assert_eq!(start_from_index, 1);

	// Check the hashes of the other blocks to ensure that all blocks came as well.
	assert_eq!(block_iter.next().unwrap().unwrap(), 1);
	assert_eq!(block_iter.next().unwrap().unwrap(), 2);
	assert_eq!(block_iter.next().unwrap().unwrap(), 3);
	assert_eq!(block_iter.next().unwrap().unwrap(), 4);
}

#[test]
fn test_non_existing_block() {
	let client = TestBlockChainClient::new();
	client.add_blocks(1, EachBlockWith::Nothing);

	let block_message = construct_new_block(1, Arc::new(client));

	assert_eq!(block_message.unwrap(), r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x1","extraData":"0x","gasLimit":"0xf4240","gasUsed":"0x0","hash":"0x3457d2fa2e3dd33c78ac681cf542e429becf718859053448748383af67e23218","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","number":"0x1","parentHash":"0x0cd786a2425d16f152c658316c423e6ce1181e15c3295826d7c9904cba9ce303","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","sealFields":[],"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x1ce","stateRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","timestamp":"0x0","totalDifficulty":null,"transactions":[],"transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","uncles":[]}"#);
}

#[test]
fn should_construct_new_block() {
	let client = TestBlockChainClient::new();
	client.add_blocks(1, EachBlockWith::Nothing);

	let block_message = construct_new_block(2, Arc::new(client));

	assert_eq!(block_message, None);
}
