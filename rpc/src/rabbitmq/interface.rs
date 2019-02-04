use v1::{EthClient, Eth};
use ethcore::client::BlockChainClient;
use sync::SyncProvider;
use ethcore::snapshot::SnapshotService;
use ethcore::miner::{self, MinerService};
use miner::external::ExternalMinerService;
use failure::Error;
use futures::future::Future;
use lapin;
use lapin::channel::{BasicPublishOptions, BasicProperties, QueueDeclareOptions};
use lapin::client::ConnectionOptions;
use lapin::types::FieldTable;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;


// Will use RabbitMQ in the future as transport protocol
/// RabbitMQ interface.
pub struct Interface<C, SN: ?Sized, S: ?Sized, M, EM> where
	C: miner::BlockChainClient + BlockChainClient,
	SN: SnapshotService,
	S: SyncProvider,
	M: MinerService,
	EM: ExternalMinerService,
{
	pub eth_client: EthClient<C, SN, S, M, EM>,
}

impl<C, SN: ?Sized, S: ?Sized, M, EM> Interface<C, SN, S, M, EM> where
	C: miner::BlockChainClient + BlockChainClient,
	SN: SnapshotService,
	S: SyncProvider,
	M: MinerService,
	EM: ExternalMinerService,
	EthClient<C, SN, S, M, EM>: Eth
{

	/// Print new blocks to stdout
	pub fn get_last_block(&self) {
		// Publish last block number to RabbitMQ
		let response = &self.eth_client.block_number().unwrap();
		println!("Latest Block --> {:?}", response);

		// Connect to a RabbitMQ server running locally
		let addr = "127.0.0.1:5672".parse().unwrap();

		Runtime::new().unwrap().block_on_all(
			TcpStream::connect(&addr).map_err(Error::from).and_then(|stream| {
				// connect() returns a future of an AMQP Client
				// that resolves once the handshake is done
				lapin::client::Client::connect(stream, ConnectionOptions::default()).map_err(Error::from)
			}).and_then(|(client, _ /* heartbeat */)| {
				// create_channel returns a future that is resolved
				// once the channel is successfully created
				client.create_channel().map_err(Error::from)
			}).and_then(|channel| {
				let id = channel.id;
				println!("created channel with id: {:?}", id);
				channel.queue_declare("interface", QueueDeclareOptions::default(), FieldTable::new()).and_then(move |_| {
					println!("channel {:?} declared queue {:?}", id, "interface");
					channel.basic_publish("", "test", b"Hello World".to_vec(), BasicPublishOptions::default(), BasicProperties::default())
				}).map_err(Error::from)
			})
		).expect("runtime failure");
	}
}
