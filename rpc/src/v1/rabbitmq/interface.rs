//! RabbitMQ broker interface

use std::net::SocketAddr;

use failure::Error;
use futures::future::Future;
use lapin::channel::{BasicPublishOptions, BasicProperties, ExchangeDeclareOptions};
use lapin::client::ConnectionOptions;
use lapin::types::FieldTable;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

#[derive(Debug, Clone, PartialEq)]
pub struct RabbitMqConfig {
	pub hostname: String,
	pub port: u16
}

/// RabbitMQ interface using lapin
pub struct RabbitMqInterface {
	config: RabbitMqConfig
}

impl RabbitMqInterface {
	pub fn new(config: RabbitMqConfig) -> Self {
		Self {
			config: config
		}
	}

	/// Publish a new message to the defined queue
	pub fn publish(&self, serialized_data: String, exchange_name: &'static str) {
		let url = format!("{}:{}", self.config.hostname, self.config.port).parse().unwrap();
		Runtime::new().unwrap().block_on_all(
			TcpStream::connect(&url).map_err(Error::from).and_then(|stream| {
				lapin::client::Client::connect(stream, ConnectionOptions::default()).map_err(Error::from)
			}).and_then(|(client, _ /* heartbeat */)| {
				client.create_channel().map_err(Error::from)
			}).and_then(move |channel| {
				channel.exchange_declare(exchange_name, "direct", ExchangeDeclareOptions::default(), FieldTable::new()).and_then(move |_| {
					channel.basic_publish(exchange_name, "parity", serialized_data.into_bytes(), BasicPublishOptions::default(), BasicProperties::default())
				}).map_err(Error::from)
			})
		).expect("Runtime failure");
	}

	/// Listen and consume incoming message
	fn consume() {
		
	}
}
