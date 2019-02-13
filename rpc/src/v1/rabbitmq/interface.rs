// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! RabbitMQ ChainNotfiy implementation

use std::net::SocketAddr;

use failure::Error;
use futures::future::Future;
use lapin::channel::{BasicPublishOptions, BasicProperties, QueueDeclareOptions};
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
	pub fn publish(&self, serialized_block: String, queue_name: &'static str) {
		let url = format!("{}:{}", self.config.hostname, self.config.port).parse().unwrap();
		Runtime::new().unwrap().block_on_all(
			TcpStream::connect(&url).map_err(Error::from).and_then(|stream| {
				lapin::client::Client::connect(stream, ConnectionOptions::default()).map_err(Error::from)
			}).and_then(|(client, _ /* heartbeat */)| {
				client.create_channel().map_err(Error::from)
			}).and_then(move |channel| {
				channel.queue_declare(queue_name, QueueDeclareOptions::default(), FieldTable::new()).and_then(move |_| {
					channel.basic_publish("", queue_name, serialized_block.into_bytes(), BasicPublishOptions::default(), BasicProperties::default())
				}).map_err(Error::from)
			})
		).expect("Runtime failure");
	}

	/// Listen and consume incoming message
	fn consume() {
		
	}
}