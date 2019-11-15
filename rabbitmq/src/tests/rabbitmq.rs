use byteorder::{LittleEndian, ByteOrder};
use futures::Stream;
use kvdb::DBTransaction;
use kvdb_memorydb;
use tokio::sync::mpsc::channel;
use std::sync::Arc;

use std::time::Duration;

use client::PubSubClient;
use ethcore::client::{
	ChainNotify, ChainRoute, ChainRouteType, EachBlockWith, NewBlocks, TestBlockChainClient,
};
use parity_runtime::Executor;

const DURATION_ZERO: Duration = Duration::from_millis(0);
const ONE: u64 = 1;

#[test]
fn should_subscribe_to_new_blocks() {
	let mut client = TestBlockChainClient::new();
	// Insert some blocks
	client.add_blocks(3, EachBlockWith::Nothing);
	let h3 = client.block_hash_delta_minus(1);
	let h2 = client.block_hash_delta_minus(2);
	let h1 = client.block_hash_delta_minus(3);

	// Create a sync_channel with buffer size 3
	let (sender, receiver) = channel::<u64>(3);
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
			(h2, ChainRouteType::Enacted),
			(h3, ChainRouteType::Enacted),
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
	assert_eq!(new_block, 2);

	let new_block = block_receiver.next().unwrap().unwrap();
	assert_eq!(new_block, 3);
}
