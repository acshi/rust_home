use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::io;

extern crate http;
extern crate chrono;
extern crate rand;
extern crate thread_pool;
extern crate regex;
#[macro_use] extern crate lazy_static;

use http::{Response};
use chrono::prelude::Local;
use rand::{Rng, OsRng};
use thread_pool::ThreadPool;
use regex::Regex;

fn write_response(mut stream: TcpStream, response: Response<&str>) -> Result<(), io::Error> {
	let (parts, body) = response.into_parts();
	stream.write(format!("{:?} {} {}\r\n",
		parts.version,
		parts.status.as_str(),
		parts.status.canonical_reason().unwrap()).as_bytes())?;

	for (field, value) in parts.headers {
		stream.write(format!("{}: {}\r\n", field.unwrap().as_str(), value.to_str().unwrap()).as_bytes())?;
	}

	let body_bytes = body.as_bytes();

	stream.write(format!("Content-Length: {}\r\n\r\n", body_bytes.len()).as_bytes())?;
	stream.write(body_bytes)?;
	stream.flush()?;
	Ok(())
}

fn ok_response(body: &str) -> Response<&str> {
	return Response::builder()
		.header("Date", &Local::now().to_rfc2822()[..])
		.header("Content-Type", "text/html")
		.body(body)
		.unwrap();
}

fn not_found_response(body: &str) -> Response<&str> {
	return Response::builder()
		.header("Date", &Local::now().to_rfc2822()[..])
		.header("Content-Type", "text/html")
		.status(404)
		.body(body)
		.unwrap();
}

fn not_authorized_response() -> Response<&str> {
	return Response::builder()
		.header("Date", &Local::now().to_rfc2822()[..])
		.header("Content-Type", "text/html")
		.status(403)
		.body("<html>403 Forbidden</html>")
		.unwrap();
}

fn parse_request(req: &str) -> Option<(&str, &str)> {
	lazy_static! {
		static ref RE: Regex = Regex::new("GET (/[\\x1F-\\x3E\\x40-\\x7F]*)(?:\\?([\\x1F-\\x7F]*))? HTTP/1\\.1").unwrap();
	}

	match RE.captures(req) {
		Some(ref capture) => {
			let path = &capture.get(1).unwrap().as_str();
			let query = match &capture.get(2) { &Some(m) => m.as_str(), &None => &"" };
			Some((path, query))
		},
		None => None
	}
}

fn login(query: &str) -> Response<&str> {
	lazy_static! {
		static ref RE: Regex = Regex::new("username=[a-zA-Z0-9\-_\.~]+&password=[a-zA-Z0-9\-_\.~]+").unwrap();
	}

	match RE.captures(req) {
		Some(ref capture) => {
			let username = &capture.get(1).unwrap().as_str();
			let password = &capture.get(2).unwrap().as_str();

		},
		None => not_authorized_response()
	}

	return ok_response("<html>Yay, logged in!</html>");
}

fn handle_client(mut stream: TcpStream) {

	let mut crypt_rng = OsRng::new().unwrap();
	println!("Random u32: {}", crypt_rng.next_u32());

	let mut buffer = [0; 512];
	stream.read(&mut buffer).unwrap();
	let request_str = String::from_utf8_lossy(&buffer[..]);

	if let Some((path, query)) = parse_request(&request_str) {
		println!("GET: {}", path);
		let response = match path {
			"/" => ok_response("<html>Hello, World!</html>"),
			"/login" => login(query),
			_ => not_found_response("<html>404 Not Found</html>")
		};
		match write_response(stream, response) {
			Ok(_) => (),
			Err(_) => ()
		}
	} else {
		println!("Invalid request");
	}
}

fn main() {
	let listener = TcpListener::bind("127.0.0.1:9000").unwrap();
	let (sender, _) = ThreadPool::fixed_size(10);

	// accept connections and process them serially
	for stream in listener.incoming() {
		match stream {
			Ok(stream) => {
				sender.send(|| {
					handle_client(stream);
				}).unwrap();
			}
			Err(_) => { /* connection failed */ }
		}
	}
}
