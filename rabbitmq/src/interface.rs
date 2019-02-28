//! RabbitMQ broker interface

use failure::Error;
use futures::future::Future;
use futures::Stream;
use lapin::channel::{
	BasicConsumeOptions, BasicGetOptions, BasicProperties, BasicPublishOptions,
	ConfirmSelectOptions, ExchangeDeclareOptions, QueueDeclareOptions,
};
use lapin::client::{Client, ConnectionOptions};
use lapin::message::Delivery;
use lapin::types::FieldTable;
use std::net::ToSocketAddrs;
use tokio::{net::TcpStream, runtime::Runtime};

use handler::Handler;
use ethereum_types::H256;

use TOPIC_EXCHANGE;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RabbitMqConfig {
	pub hostname: String,
	pub port: u16,
}

/// RabbitMQ interface using lapin
pub struct RabbitMqInterface {
	config: RabbitMqConfig,
}

impl RabbitMqInterface {
	// Create a new RabbitMQ Interface
	pub fn new(config: RabbitMqConfig) -> Self {
		Self { config: config }
	}
}

pub trait Interface {
	// Publish a new message to a topic exchange
	fn topic_publish(
		&self,
		serialized_data: String,
		exchange_name: &'static str,
		routing_key: &'static str,
	);
	// Listen and consume incoming message
	fn consume(
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
		exchange_name: &'static str,
		routing_key: &'static str,
	) {
		let mut socket_addrs = format!("{}:{}", self.config.hostname, self.config.port)
			.to_socket_addrs()
			.unwrap()
			.filter(|addr| addr.is_ipv4());
		Runtime::new()
			.unwrap()
			.block_on_all(
				TcpStream::connect(&socket_addrs.next().unwrap())
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
					.and_then(move |(client, _ /*heartbeat*/)| {
						client
							.create_confirm_channel(ConfirmSelectOptions::default())
							.map_err(Error::from)
					})
					.and_then(move |channel| {
						channel
							.clone()
							.exchange_declare(
								exchange_name,
								TOPIC_EXCHANGE,
								ExchangeDeclareOptions::default(),
								FieldTable::new(),
							)
							.map_err(Error::from)
							.map(move |_| channel)
					})
					.and_then(move |channel| {
						channel
							.basic_publish(
								exchange_name,
								routing_key,
								serialized_data.into_bytes(),
								BasicPublishOptions::default(),
								BasicProperties::default(),
							)
							.map_err(Error::from)
							.map(|confirmation| {
								info!("got confirmation of publication: {:?}", confirmation);
							})
					})
					.map_err(|err| eprintln!("An error occured: {}", err)),
			)
			.expect("runtime exited with failure");
	}

	/// Listen and consume incoming message
	fn consume(
		&self,
		consumer_name: &'static str,
		queue_name: &'static str,
		handler: Box<Handler>,
	) -> Result<(), Error> {
		let mut socket_addrs = format!("{}:{}", self.config.hostname, self.config.port)
			.to_socket_addrs()
			.unwrap()
			.filter(|addr| addr.is_ipv4());

		let rt = TcpStream::connect(&socket_addrs.next().unwrap())
			.map_err(Error::from)
			.and_then(|stream| {
				lapin::client::Client::connect(
					stream,
					ConnectionOptions {
						frame_max: 65535,
						heartbeat: 20,
						..Default::default()
					},
				)
				.map_err(Error::from)
			})
			.and_then(move |(client, heartbeat)| {
				tokio::spawn(heartbeat.map_err(|e| error!("heartbeat error: {}", e)));
				client
					.create_channel()
					.and_then(move |channel| {
						let id = channel.id;
						info!("created channel with id: {}", id);

						let c = channel.clone();
						channel
							.queue_declare(
								queue_name,
								QueueDeclareOptions::default(),
								FieldTable::new(),
							)
							.and_then(move |queue| {
								info!("channel {} declared queue {:?}", id, queue);
								let ch = channel.clone();
								channel
									.basic_get(queue_name, BasicGetOptions::default())
									.and_then(move |message| {
										info!("got message: {:?}", message);
										channel.basic_ack(message.delivery.delivery_tag, false)
									})
									.and_then(move |_| {
										ch.basic_consume(
											&queue,
											consumer_name,
											BasicConsumeOptions::default(),
											FieldTable::new(),
										)
									})
							})
							.and_then(|stream| {
								info!("got consumer stream");
								stream.for_each(move |message| {
									let tag = message.delivery_tag;
									if let Err(e) = handle_message(message, &handler) {
										error!("failed to send transaction: {:?}", e);
									}
									c.basic_ack(tag, false)
								})
							})
					})
					.map_err(Error::from)
			});

		Runtime::new()?.block_on_all(rt)?;
		Ok(())
	}
}

pub fn handle_message(msg: Delivery, hnd: &Box<Handler>) -> Result<H256, Error> {
	let id: Result<String, Error> = match msg.properties.message_id() {
		Some(v) => Ok(v.to_string()),
		None => Err(format_err!("Empty message id")),
	};
	let id = id?;
	info!("consume message {}", id);
	hnd.send_transaction(id, &msg.data)
}
