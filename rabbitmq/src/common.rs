use failure::Error as FailureError;
use futures::Future;
use log::error;

use std::process;

pub fn handle_fatal_error(error: FailureError) {
	let pretty_error = error
		.iter_causes()
		.fold(error.to_string(), |mut res, cause| {
			res.push_str(": ");
			res.push_str(&cause.to_string());
			res
		});
	error!("{}", pretty_error);
	process::exit(1);
}

pub fn try_spawn<F, I, E>(future: F)
where
	F: Future<Item = I, Error = E> + Send + 'static,
	E: Into<FailureError>,
{
	tokio::spawn(future.map(|_| ()).map_err(|err| {
		handle_fatal_error(err.into());
	}));
}