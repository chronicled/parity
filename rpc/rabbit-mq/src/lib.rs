extern crate jsonrpc_core as rpc;
extern crate serde;
extern crate serde_json;

#[derive(Debug)]
// RPC simple test.
// Will use RabbitMQ in the future as transport protocol
pub struct Rpc<M: rpc::Metadata = (), S: rpc::Middleware<M> = rpc::middleware::Noop> {
	pub io: rpc::MetaIoHandler<M, S>,
}

impl <M: rpc::Metadata + Default, S: rpc::Middleware<M>> Rpc<M, S> {
	/// Create a new RPC instance from a single delegate.
	pub fn new(handler: rpc::MetaIoHandler<M, S>) -> Self {
		Rpc { io: handler }
	}

	/// Perform a single, synchronous method call and return pretty-printed value
	pub fn request<T>(&self, method: &str, params: &T) -> String where
		T: serde::Serialize,
	{
		self.make_request(method, params)
	}

	/// Perform a single, synchronous method call.
	pub fn make_request<T>(
		&self,
		method: &str,
		params: &T,
	) -> String where
		T: serde::Serialize
	{
		use self::rpc::types::response;

		let request = format!(
			"{{ \"jsonrpc\":\"2.0\", \"id\": 1, \"method\": \"{}\", \"params\": {} }}",
			method,
			serde_json::to_string_pretty(params).expect("Serialization should be infallible."),
		);

		let response = self.io
			.handle_request_sync(&request, M::default())
			.expect("We are sending a method call not notification.");

		let extracted = match serde_json::from_str(&response).expect("We will always get a single output.") {
			response::Output::Success(response::Success { result, .. }) => {
				serde_json::to_string_pretty(&result)
			},
			response::Output::Failure(response::Failure { error, .. }) => {
				serde_json::to_string_pretty(&error)
			},
		}.expect("Serialization is infallible; qed");

		println!("\n{}\n --> {}\n", request, extracted);

		extracted
	}
}
