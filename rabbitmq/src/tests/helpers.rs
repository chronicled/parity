//! RabbitMQ dummy interface
use std::sync::mpsc::SyncSender;

use interface::{Interface, RabbitMqConfig};

/// Dummy RabbitMQ interface
pub struct DummyRabbitMqInterface {
	pub config: RabbitMqConfig,
	pub sender: SyncSender<String>,
}

impl Interface for DummyRabbitMqInterface {
	/// Publish a new message to a topic exchange
	fn topic_publish(&self, serialized_data: String, exchange_name: &'static str, routing_key: &'static str) {
		println!("supposed to publish to the {:?}, exchange with the routing key: {:?}", exchange_name, routing_key);
		self.sender.send(serialized_data);
	}

	/// Listen and consume incoming message
	fn consume() {
		
	}
}
