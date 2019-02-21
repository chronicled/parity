//! RabbitMQ broker interface

use failure::Error;
use futures::future::Future;
use lapin::channel::{BasicPublishOptions, BasicProperties, ConfirmSelectOptions, ExchangeDeclareOptions};
use lapin::client::{Client, ConnectionOptions};
use lapin::types::FieldTable;
use std::net::{ToSocketAddrs};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

use TOPIC_EXCHANGE;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RabbitMqConfig {
	pub hostname: String,
	pub port: u16
}

/// RabbitMQ interface using lapin
pub struct RabbitMqInterface {
	config: RabbitMqConfig
}

impl RabbitMqInterface {
	// Create a new RabbitMQ Interface
	pub fn new(config: RabbitMqConfig) -> Self {
		Self {
			config: config
		}
	}
}

pub trait Interface {
	// Publish a new message to a topic exchange
	fn topic_publish(&self, serialized_data: String, exchange_name: &'static str, routing_key: &'static str);
	// Listen and consume incoming message
	fn consume();
}

impl Interface for RabbitMqInterface {
	/// Publish a new message to a topic exchange
	fn topic_publish(&self, serialized_data: String, exchange_name: &'static str, routing_key: &'static str) {
		let mut socket_addrs = format!("{}:{}", self.config.hostname, self.config.port)
			.to_socket_addrs()
			.unwrap()
			.filter(|addr| addr.is_ipv4());
		Runtime::new().unwrap().block_on_all(
			TcpStream::connect(&socket_addrs.next().unwrap()).map_err(Error::from).and_then(|stream| {
				Client::connect(stream, ConnectionOptions {
					frame_max: 65535,
					heartbeat: 20,
					..Default::default()
				}).map_err(Error::from)
			}).and_then(move |(client, _ /*heartbeat*/)| {
				client.create_confirm_channel(ConfirmSelectOptions::default()).map_err(Error::from)
			}).and_then(move |channel| {
				channel.clone().exchange_declare(exchange_name, TOPIC_EXCHANGE, ExchangeDeclareOptions::default(), FieldTable::new())
					.map_err(Error::from)
					.map(move |_| channel)
			}).and_then(move |channel| {
				channel.basic_publish(exchange_name, routing_key, serialized_data.into_bytes(), BasicPublishOptions::default(), BasicProperties::default())
				.map_err(Error::from)
				.map(|confirmation| {
					println!("got confirmation of publication: {:?}", confirmation);
				})
			})
			.map_err(|err| eprintln!("An error occured: {}", err))
		).expect("runtime exited with failure");
	}

	/// Listen and consume incoming message
	fn consume() {
		
	}
}
