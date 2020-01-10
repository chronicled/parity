use client::PubSubClient;
use client::construct_new_block;
use ethcore::client::{
	ChainNotify, ChainRoute, ChainRouteType, EachBlockWith, NewBlocks, TestBlockChainClient,
};
use super::sync_provider::{Config, TestSyncProvider};
use ethereum_types::H256;
use futures::Stream;
use kvdb_memorydb;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;

const DURATION_ZERO: Duration = Duration::from_millis(0);
const ONE: u64 = 1;

#[test]
fn should_subscribe_to_new_blocks() {
	let mut client = TestBlockChainClient::new();
	// Insert some blocks
	client.add_blocks(4, EachBlockWith::Nothing);
	let h4 = client.block_hash_delta_minus(1);
	let h3 = client.block_hash_delta_minus(2);
	let h2 = client.block_hash_delta_minus(3);
	let h1 = client.block_hash_delta_minus(4);
	let test_sync = TestSyncProvider::new(Config {
		network_id: 3,
		num_peers: 5,
	});

	// Create a sync_channel with buffer size 3
	let (enacted_sender, enacted_receiver) = channel::<u64>(4);
	let (retracted_sender, retracted_receiver) = channel::<H256>(4);
	let dummy_rabbitmq_client = PubSubClient {
		blockchain_client: Arc::new(client),
		sync: Arc::new(test_sync),
		enacted_sender: enacted_sender,
		retracted_sender: retracted_sender,
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
	let mut enacted = enacted_receiver.wait();
	let mut retracted = retracted_receiver.wait();

	let new_block = enacted.next().unwrap().unwrap();
	assert_eq!(new_block, 1);

	let retracted_block = retracted.next().unwrap().unwrap();
	assert_eq!(
		retracted_block,
		H256::from_str("44e5ecf454ea99af9d8a8f2ca0daba96964c90de05db7a78f59b84ae9e749706").unwrap()
	);

	let new_block = enacted.next().unwrap().unwrap();
	assert_eq!(new_block, 3);

	let new_block = enacted.next().unwrap().unwrap();
	assert_eq!(new_block, 4);
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
