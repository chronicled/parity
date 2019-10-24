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

const DURATION_ZERO: Duration = Duration::from_millis(0);

#[test]
fn should_subscribe_to_new_blocks() {
	let mut client = TestBlockChainClient::new();
	// Insert some blocks
	client.add_blocks(3, EachBlockWith::Nothing);
	let h3 = client.block_hash_delta_minus(1);
	let h2 = client.block_hash_delta_minus(2);
	let h1 = client.block_hash_delta_minus(3);

	// Create a sync_channel with buffer size 3
	let (sender, receiver) = channel::<Vec<u8>>(3);
	let dummy_rabbitmq_client = PubSubClient {
		client: Arc::new(client),
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
	let block_str = std::str::from_utf8(&new_block).unwrap();
	let response = r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x1","extraData":"0x","gasLimit":"0xf4240","gasUsed":"0x0","hash":"0x3457d2fa2e3dd33c78ac681cf542e429becf718859053448748383af67e23218","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","number":"0x1","parentHash":"0x0cd786a2425d16f152c658316c423e6ce1181e15c3295826d7c9904cba9ce303","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","sealFields":[],"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x1ce","stateRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","timestamp":"0x0","totalDifficulty":null,"transactions":[],"transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","uncles":[]}"#;
	assert_eq!(block_str, response);

	let new_block = block_receiver.next().unwrap().unwrap();
	let block_str = std::str::from_utf8(&new_block).unwrap();
	let response = r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x2","extraData":"0x","gasLimit":"0xf4240","gasUsed":"0x0","hash":"0x44e5ecf454ea99af9d8a8f2ca0daba96964c90de05db7a78f59b84ae9e749706","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","number":"0x2","parentHash":"0x3457d2fa2e3dd33c78ac681cf542e429becf718859053448748383af67e23218","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","sealFields":[],"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x1ce","stateRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","timestamp":"0x0","totalDifficulty":null,"transactions":[],"transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","uncles":[]}"#;
	assert_eq!(block_str, response);

	let new_block = block_receiver.next().unwrap().unwrap();
	let block_str = std::str::from_utf8(&new_block).unwrap();
	let response = r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x3","extraData":"0x","gasLimit":"0xf4240","gasUsed":"0x0","hash":"0xdf04a98bb0c6fa8441bd429822f65a46d0cb553f6bcef602b973e65c81497f8e","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","number":"0x3","parentHash":"0x44e5ecf454ea99af9d8a8f2ca0daba96964c90de05db7a78f59b84ae9e749706","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","sealFields":[],"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x1ce","stateRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","timestamp":"0x0","totalDifficulty":null,"transactions":[],"transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","uncles":[]}"#;
	assert_eq!(block_str, response);
	let latest_sent_block: u64 = dummy_rabbitmq_client.database.get(None, b"latest")
		.expect("low-level database error")
		.and_then(|val| {
			Some(LittleEndian::read_u64(&val[..]))
		})
		.unwrap();
	assert_eq!(latest_sent_block, 3);
}

#[test]
pub fn should_send_missed_blocks() {
	let client = TestBlockChainClient::new();
	// Insert some blocks
	client.add_blocks(6, EachBlockWith::Nothing);

	// Create a sync_channel with buffer size 3
	let (sender, receiver) = channel::<Vec<u8>>(10);
	let dummy_rabbitmq_client = PubSubClient {
		client: Arc::new(client),
		sender: sender,
		database: Arc::new(kvdb_memorydb::create(0)),
	};
	let mut transaction = DBTransaction::new();
	let highest_block_number: u64 = 4;
	transaction.put(None, b"latest", &highest_block_number.to_le_bytes());
	dummy_rabbitmq_client.database.write(transaction).unwrap();

	dummy_rabbitmq_client.send_missed_blocks().unwrap();
	let mut block_receiver = receiver.wait();

	let new_block = block_receiver.next().unwrap().unwrap();
	let block_str = std::str::from_utf8(&new_block).unwrap();
	let response = r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x5","extraData":"0x","gasLimit":"0xf4240","gasUsed":"0x0","hash":"0x03667fbd3eb38b7ba1e3e7c668915b3d51a2cc65285c079c3dd580d0ed4e0300","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","number":"0x5","parentHash":"0xd93ad77754a8302bae91221a3e4508c4427affbbfbdba766120cf2149c674321","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","sealFields":[],"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x1ce","stateRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","timestamp":"0x0","totalDifficulty":null,"transactions":[],"transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","uncles":[]}"#;
	assert_eq!(block_str, response);

	let new_block = block_receiver.next().unwrap().unwrap();
	let block_str = std::str::from_utf8(&new_block).unwrap();
	let response = r#"{"author":"0x0000000000000000000000000000000000000000","difficulty":"0x6","extraData":"0x","gasLimit":"0xf4240","gasUsed":"0x0","hash":"0x4e6c2e05f98c7c7fcbb81768b64fc6a96289ddf1c72f165b8dda43dbaae09239","logs":[],"logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","miner":"0x0000000000000000000000000000000000000000","number":"0x6","parentHash":"0x03667fbd3eb38b7ba1e3e7c668915b3d51a2cc65285c079c3dd580d0ed4e0300","receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","sealFields":[],"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","size":"0x1ce","stateRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","timestamp":"0x0","totalDifficulty":null,"transactions":[],"transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","uncles":[]}"#;
	assert_eq!(block_str, response);
	let latest_sent_block: u64 = dummy_rabbitmq_client.database.get(None, b"latest")
		.expect("low-level database error")
		.and_then(|val| {
			Some(LittleEndian::read_u64(&val[..]))
		})
		.unwrap();
	assert_eq!(latest_sent_block, 6);
}
