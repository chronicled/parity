//! RabbitMQ dummy interface
use failure::Error;
use std::sync::mpsc::SyncSender;

use handler::Handler;
use interface::{Interface, RabbitMqConfig};

/// Dummy RabbitMQ interface
pub struct DummyRabbitMqInterface {
	pub config: RabbitMqConfig,
	pub sender: SyncSender<String>,
}

impl Interface for DummyRabbitMqInterface {
	/// Publish a new message to a topic exchange
	fn topic_publish(
		&self,
		serialized_data: String,
		exchange_name: &'static str,
		routing_key: &'static str,
	) -> Result<(), Error> {
		println!(
			"supposed to publish to the {:?}, exchange with the routing key: {:?}",
			exchange_name, routing_key
		);
		self.sender.send(serialized_data);
		Ok(())
	}

	/// Listen and consume incoming message
	fn spawn_consumer(
		&self,
		consumer_name: &'static str,
		queue_name: &'static str,
		handler: Box<Handler>,
	) -> Result<(), Error> {
		Ok(())
	}
}
