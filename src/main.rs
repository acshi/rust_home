extern crate rand;
extern crate iron;
extern crate handlebars_iron as hbs;
extern crate router;
extern crate serde_json;
extern crate urlencoded;
extern crate config;
extern crate ring_pwhash;
extern crate time;
extern crate chrono;

use iron::prelude::*;
use iron::{status, typemap, Handler, headers, AfterMiddleware, Chain};
use hbs::{Template, HandlebarsEngine, DirectorySource};
// use hbs::handlebars::{Handlebars, RenderContext, RenderError, Helper};
use router::Router;
use hbs::handlebars::to_json;
use serde_json::value::{Value, Map};
use urlencoded::UrlEncodedQuery;
use rand::{Rng, OsRng};
use ring_pwhash::scrypt;
use time::Duration;
use chrono::{DateTime, Utc};

struct ScryptParams;
impl typemap::Key for ScryptParams { type Value = scrypt::ScryptParams; }

struct Users;
impl typemap::Key for Users{ type Value = Vec<User>; }

#[derive(Debug, Clone)]
struct User {
	pub username: String,
	pub user_index: usize,
	pub salt: [u8; 16],
	pub hash: [u8; 32],
}

fn user_for_name<'a>(users: &'a Vec<User>, username: &str) -> Option<&'a User> {
	for user in users {
		if user.username == username {
			return Some(user);
		}
	}
	return None;
}

struct Sessions;
impl typemap::Key for Sessions{ type Value = Vec<Session>; }

#[derive(Debug, Clone)]
struct Session {
	pub key: [u8; 32],
	pub user_index: usize,
	pub expiration: DateTime<Utc>,
}
impl typemap::Key for Session{ type Value = Session; }

fn make_data(req: &mut Request) -> Map<String, Value> {
	let mut data = Map::new();
	let user = logged_in_user(req);
	if let Some(user) = user {
		data.insert("username".to_string(), to_json(&user.username.to_owned()));
	}
	data
}

fn forbidden() -> IronResult<Response> {
	return Ok(Response::with((status::Forbidden, "<html>403 Forbidden</html>")));
}

fn buffer_to_hex_str(buffer: &[u8]) -> String {
	let mut string = String::from("");
	for b in buffer {
		string.push_str(&format!("{:02x}", b));
	}
	return string;
}

fn logged_in_user(req: &mut Request) -> Option<User> {
	let users = req.extensions.get::<Users>().unwrap();
	let sessions = req.extensions.get::<Sessions>().unwrap();

	let session_key = match req.headers.get::<headers::Cookie>() {
		Some(cookies) => {
			let mut buff = [0u8; 32];
			for c in &cookies.0 {
				if c.starts_with("session") {
					let key_str = c.split("session=").nth(1).unwrap();
					read_hex_str(key_str, &mut buff);
					break
				}
			}
			buff
		},
		None => return None
	};

	for s in sessions {
		if s.key == session_key {
			return Some(users[s.user_index].clone());
		}
	}
	return None;
}

fn make_session_key() -> [u8; 32] {
	let mut crypt_rng = OsRng::new().unwrap();
	let mut key = [0u8; 32];
	crypt_rng.fill_bytes(&mut key);
	key
}

fn login(req: &mut Request) -> IronResult<Response> {
	let username;
	let password;
	{
		let hashmap = req.get::<UrlEncodedQuery>();// handle this and related.
		if hashmap.is_err() {
			return forbidden();
		}
		let hashmap = hashmap.unwrap();
		if !hashmap.contains_key("username") || !hashmap.contains_key("password") {
			return forbidden();
		}
		username = hashmap.get("username").unwrap()[0].to_owned();
		password = hashmap.get("password").unwrap()[0].to_owned();
	}

	let users = req.extensions.get::<Users>().unwrap();
	let user = user_for_name(&users, &username);
	if user.is_none() {
		println!("user not found");
		return forbidden();
	}

	let user = user.unwrap();

	let params = req.extensions.get::<ScryptParams>().unwrap();
	let mut hash = [0u8; 32];
	scrypt::scrypt(password.as_bytes(), &user.salt, params, &mut hash);
	println!("computed hash\t [{}]", buffer_to_hex_str(&hash));
	println!("actual hash\t [{}]", buffer_to_hex_str(&user.hash));
	if hash == user.hash {
		let mut resp = Response::with((status::Ok, "<html>Yay, logged in!</html>"));
		let session_key = make_session_key();
		let key_str = buffer_to_hex_str(&session_key);
		let expr_date = Utc::now() + Duration::days(2);
		let cookie = format!("session={}; Expires={}; HttpOnly", key_str, expr_date.to_rfc2822());
		resp.headers.set(headers::SetCookie(vec![cookie]));
		resp.extensions.insert::<Session>(Session {
				key: session_key,
				user_index: user.user_index,
				expiration: expr_date,
		});
		return Ok(resp);
	}
	return forbidden();
}

fn index(req: &mut Request) -> IronResult<Response> {
	let mut resp = Response::with(status::Ok);
	resp.set_mut(Template::new("index", make_data(req)));
	return Ok(resp);
}

fn not_found(req: &mut Request) -> IronResult<Response> {
	//return Ok(Response::with((status::NotFound, "<html>404 Not Found</html>")));
	return Ok(Response::with((status::NotFound, Template::new("404", make_data(req)))));
}

fn read_hex_str(hex_str: &str, output: &mut [u8]) {
	if hex_str.len() != 2 * output.len() {
		eprintln!("Error hex string does not have {} bytes of hex", output.len());
		return;
	}
	for i in 0..output.len() {
		output[i] = u8::from_str_radix(&hex_str[i*2..i*2+2], 16).unwrap();
	}
}

struct DefaultContentType;
impl AfterMiddleware for DefaultContentType {
    // This is run for every requests, AFTER all handlers have been executed
    fn after(&self, _: &mut Request, mut resp: Response) -> IronResult<Response> {
        if resp.headers.get::<headers::ContentType>() == None {
            resp.headers.set(headers::ContentType::html());
        }
        Ok(resp)
    }
}

fn main() {
	let mut settings = config::Config::default();
	match settings.merge(config::File::with_name("settings")) {
		Ok(_) => (),
		Err(e) => {
			eprintln!("Error opening settings.toml file: {}", e);
			std::process::exit(-1);
		}
	}
	settings.set_default("scrypt.log_n", 15).unwrap();
	settings.set_default("scrypt.r", 8).unwrap();
	settings.set_default("scrypt.p", 1).unwrap();
	let users = match settings.get_array("users") {
		Ok(vals) => {
			let mut users = Vec::new();
			let mut user_index = 0;
			for v in vals {
				let v = v.into_table().unwrap();
				let username = v.get("username").unwrap().clone().into_str().unwrap().to_owned();
				let salt_str = v.get("salt").unwrap().clone().into_str().unwrap();
				let hash_str = v.get("hash").unwrap().clone().into_str().unwrap();
				if salt_str.len() != 32 || hash_str.len() != 64 {
					eprintln!("Error in settings.toml: salt must be 16-bytes of hex, hash must be 32-bytes of hex for user {}", username);
					std::process::exit(-1);
				}
				let mut salt = [0u8; 16];
				let mut hash = [0u8; 32];
				read_hex_str(&salt_str, &mut salt[..]);
				read_hex_str(&hash_str, &mut hash[..]);

				users.push(User { username, user_index, salt, hash });
				user_index += 1;
			}
			users
		},
		Err(e) => {
			eprintln!("Settings.toml file is missing entry for [[users]]: {}", e);
			std::process::exit(-1);
		}
	};
	println!("users: {:?}", users[0]);

	let params = scrypt::ScryptParams::new(
					settings.get_int("scrypt.log_n").unwrap() as u8,
					settings.get_int("scrypt.r").unwrap() as u32,
					settings.get_int("scrypt.p").unwrap() as u32);

	let mut sessions = Vec::<Session>::new();

	let mut hbse = HandlebarsEngine::new();
	hbse.add(Box::new(DirectorySource::new("./src/templates/", ".hbs")));

	let mut router = Router::new();
	router.get("/", index, "index");
	router.get("/login", login, "login");
	router.get("*", not_found, "not_found");

	let mut chain = Chain::new(router);
	chain.link_after(hbse);
	chain.link_after(DefaultContentType);

	Iron::new(move |req: &mut Request| {
		req.extensions.insert::<ScryptParams>(params);
		req.extensions.insert::<Users>(users.clone());
		req.extensions.insert::<Sessions>(sessions.clone());
		let res = chain.handle(req);
		// check for new sessions, etc...
		// if let Ok(res) = res {
		// 	if let Some(session) = res.extensions.get::<Session>() {
		// 		sessions.push(session.clone());
		// 	}
		// }
		return res;
	}).http("127.0.0.1:9000").unwrap();
}
