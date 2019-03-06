//! RabbitMQ broker interface

use failure::{err_msg, Error, ResultExt};
use futures::future::{Future, IntoFuture};
use futures::Stream;
use lapin::channel::{
	BasicConsumeOptions, BasicProperties, BasicPublishOptions,
	ConfirmSelectOptions, ExchangeDeclareOptions, QueueDeclareOptions, Channel,
};
use lapin::client::{Client, ConnectionOptions};
use lapin::consumer::Consumer;
use lapin::queue::Queue;
use lapin::types::FieldTable;
use std::net::ToSocketAddrs;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

use handler::Handler;

use LOG_TARGET;
use TOPIC_EXCHANGE;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RabbitMqConfig {
	pub hostname: String,
	pub port: u16,
}

/// RabbitMQ interface using lapin
pub struct RabbitMqInterface {
	config: RabbitMqConfig,
	runtime: Option<Arc<Mutex<Runtime>>>,
	client: Option<Client<TcpStream>>,
	channel: Option<Channel<TcpStream>>,
}

impl Default for RabbitMqInterface {
	fn default() -> RabbitMqInterface {
		let config = RabbitMqConfig::default();
		RabbitMqInterface {
			config: config,
			runtime: None,
			client: None,
			channel: None,
		}
	}
}

impl RabbitMqInterface {
	// Create a new RabbitMQ Interface
	pub fn new(config: RabbitMqConfig) -> Self {
		let rt = Some(Arc::new(Mutex::new(Runtime::new().unwrap())));
		RabbitMqInterface {
			config: config,
			runtime: rt,
			..Default::default()
		}
	}

	fn get_channel(&self) -> Result<&Channel<TcpStream>, Error> {
		self.channel
		.as_ref()
		.ok_or(err_msg("No channel to RabbitMQ available"))
	}

	pub fn connect(&mut self) -> Result<&Self, Error> {
		let socket_addrs = format!("{}:{}", self.config.hostname, self.config.port)
		.to_socket_addrs()
		.context("Failed to get the socket address from the hostname parameter")?
		.filter(|addr| addr.is_ipv4())
		.next()
		.ok_or(err_msg("Couldn't find the RabbitMQ server socket address"))?;
		let runtime = self.runtime.clone().unwrap();
		let mut lock = runtime.lock().unwrap();
		let result = lock.block_on(
			TcpStream::connect(&socket_addrs)
			.map_err(Error::from)
			.and_then(|stream| {
				Client::connect(
					stream,
					ConnectionOptions {
						frame_max: 65535,
						heartbeat: 20,
						..Default::default()
					},
				)
				.map_err(Error::from)
			})
			.and_then(|(client, heartbeat)| {
				tokio::spawn(heartbeat.map_err(|e| eprintln!("heartbeat error: {}", e)))
				.into_future()
				.map(|_| client)
				.map_err(|_| err_msg("Couldn't spawn the heartbeat task"))
			})
			.and_then(|client| {
				client
				.create_confirm_channel(ConfirmSelectOptions::default())
				.map_err(Error::from)
				.map(|channel| (client, channel))
			}),
		)
		.map_err(Error::from);

	let (client, channel) = result?;
	info!(
		target: LOG_TARGET,
		"Connected to RabbitMQ server at {}:{}", self.config.hostname, self.config.port
	);
	self.client = Some(client);
	self.channel = Some(channel);
	Ok(self)
	}

	fn create_topic_exchange(&self, name: &'static str) -> Result<&Self, Error> {
		let channel = self.get_channel()?.clone();
		let runtime = self.runtime.clone().unwrap();
		let mut lock = runtime.lock().unwrap();
		lock.block_on(channel.exchange_declare(
			name,
			TOPIC_EXCHANGE,
			ExchangeDeclareOptions {
				durable: true,
				..Default::default()
			},
			FieldTable::new(),
		))
		.map_err(Error::from)?;
		info!(target: LOG_TARGET, "Created a topic exchange \"{}\"", name);
		Ok(self)
	}

	pub fn create_queue(&self, name: &'static str) -> Result<&Self, Error> {
		let channel = self.get_channel()?.clone();
		let runtime = self.runtime.clone().unwrap();
		let mut lock = runtime.lock().unwrap();
		lock.block_on(channel.queue_declare(
			name,
			QueueDeclareOptions {
				durable: true,
				..Default::default()
			},
			FieldTable::new(),
		))
		.map_err(Error::from)?;
		info!(target: LOG_TARGET, "Created a queue \"{}\"", name);
		Ok(self)
	}

	fn register_consumer(
		&self,
		queue_name: &'static str,
		consumer_name: &'static str,
	) -> Result<impl Future<Item = Consumer<TcpStream>, Error = lapin::error::Error>, Error> {
		let channel = self.get_channel()?.clone();
		let queue = Queue::new(queue_name.to_string(), 0, 0);
		let consumer = channel.basic_consume(
			&queue,
			&consumer_name,
			BasicConsumeOptions::default(),
			FieldTable::new(),
		);
		Ok(consumer)
	}

	pub fn publish(
		&self,
		serialized_data: String,
		exchange: &'static str,
		topic: &'static str,
	) -> Result<&Self, Error> {
		let runtime = self.runtime.clone().unwrap();
		let mut lock = runtime.lock().unwrap();
		lock.block_on(
			self.get_channel()?
			.basic_publish(
				exchange,
				topic,
				serialized_data.into_bytes(),
				BasicPublishOptions::default(),
				BasicProperties::default(),
			)
			.map(|confirmation| {
				info!(
					target: LOG_TARGET,
					"publish got confirmation: {:?}", confirmation
				)
			}),
		)
		.map_err(Error::from)?;
		info!(
			target: LOG_TARGET,
			"Published message {}, {}", exchange, topic
		);
		Ok(self)
	}

	fn disconnect(self) -> Result<(), Error> {
		let runtime = self.runtime.clone().unwrap();
		let mut lock = runtime.lock().unwrap();
		lock.block_on(self.get_channel()?.close(200, "Bye"))
		.map_err(Error::from)?;
		Ok(())
	}

	fn spawn<F>(&self, future: F) -> Result<(), Error>
	where
	F: Future<Item = (), Error = ()> + 'static + std::marker::Send,
	{
		let runtime = self.runtime.clone().unwrap();
		let mut lock = runtime.lock().unwrap();
		lock.spawn(future);
		Ok(())
	}
}

pub trait Interface {
	// Publish a new message to a topic exchange
	fn topic_publish(
		&self,
		serialized_data: String,
		exchange_name: &'static str,
		routing_key: &'static str,
	) -> Result<(), Error>;
	// Listen and consume incoming message
	fn spawn_consumer(
		&self,
		consumer_name: &'static str,
		queue_name: &'static str,
		handler: Box<Handler>,
	) -> Result<(), Error>;
}

impl Interface for RabbitMqInterface {
	/// Publish a new message to a topic exchange
	fn topic_publish(
		&self,
		serialized_data: String,
		exchange: &'static str,
		topic: &'static str,
	) -> Result<(), Error> {
		self.publish(serialized_data, exchange, topic);
		Ok(())
	}
	/// Listen and consume incoming message
	fn spawn_consumer(
		&self,
		consumer_name: &'static str,
		queue_name: &'static str,
		handler: Box<Handler>,
	) -> Result<(), Error> {
		let channel = self.get_channel().unwrap().clone();
		let consumer = self.register_consumer(queue_name, consumer_name)?
			.and_then(|stream| {
				info!(target: LOG_TARGET, "got consumer stream");
				 stream.for_each(move |message| {
					let payload = std::str::from_utf8(&message.data).unwrap();
					debug!(target: LOG_TARGET, "got message: {:?}", payload);
					if let Err(e) = handler.send_transaction(&payload) {
						error!(target: LOG_TARGET, "failed to send transaction: {:?}", e);
					}
					channel.basic_ack(message.delivery_tag, false)
				})
			})
			.map_err(|_| eprintln!("Error while processing message"));
		self.spawn(consumer)
	}
}
