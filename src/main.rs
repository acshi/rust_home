#![feature(plugin)]
#![feature(custom_derive)]
#![plugin(rocket_codegen)]

extern crate rocket;
#[macro_use] extern crate rocket_contrib;
extern crate rand;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate serde_derive;
extern crate urlencoded;
extern crate config;
extern crate ring_pwhash;
extern crate time;
extern crate chrono;
#[macro_use] extern crate maplit;

use std::sync::Mutex;
use std::path::{Path, PathBuf};

use rocket::{State, Outcome};
use rocket::http::{Cookie, Cookies};
use rocket::response::{Redirect, NamedFile};
use rocket::request::{self, Form, Request, FromRequest};
use rocket_contrib::Template;
use rocket_contrib::{Json, Value};

use rand::{Rng, OsRng};
use ring_pwhash::scrypt;
use time::Duration;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
struct Session {
	pub key: [u8; 32],
	pub user_index: usize,
	pub expiration: DateTime<Utc>,
	pub csrf: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScryptParams {
    log_n: u8,
    r: u32,
    p: u32,
}

#[derive(Debug, Clone, Serialize)]
struct BoolIrDeviceData {
	id: u16,
	name: String,
	value: bool,
}

#[derive(Debug, Serialize)]
struct BoolIrDevice {
	id: u16,
	name: String,
	value: Mutex<bool>,
}

#[derive(Debug, Serialize)]
struct HomeState {
	pub scrypt_params: ScryptParams,
	pub users: Vec<User>,
	pub sessions: Mutex<Vec<Session>>,
	pub ir_key: [u8; 32],
	pub bool_ir_devices: Vec<BoolIrDevice>,
}

#[derive(Debug, Clone, Serialize)]
struct TemplateData {
	pub username: String,
	pub csrf: String,
	pub bool_ir_devices: Vec<BoolIrDeviceData>,
}

fn decode_key_cookie(req: &Request<>, cookie_name: &str) -> Option<[u8; 32]> {
	if let Outcome::Success(cookies) = Cookies::from_request(req) {
		if let Some(key_str) = cookies.get(cookie_name) {
			let mut buff = [0u8; 32];
			read_hex_str(key_str.value(), &mut buff).unwrap();
			return Some(buff);
		}
	}
	None
}

impl<'a, 'r> FromRequest<'a, 'r> for Session {
	type Error = ();
	fn from_request(req: &'a Request<'r>) -> request::Outcome<Session, ()> {
		let state = State::<HomeState>::from_request(req);
		if let Outcome::Success(state) = state {
			let session_key = decode_key_cookie(req, "session");
			if let Some(session_key) = session_key {
				let mut sessions = state.sessions.lock().unwrap();
				let session_index = sessions.iter().position(|s| s.key == session_key);
				if let Some(session_index) = session_index {
					if sessions[session_index].expiration <= Utc::now() {
						sessions.swap_remove(session_index);
						return Outcome::Forward(());
					}
					return Outcome::Success(sessions[session_index].clone());
				}
			}
		}
		Outcome::Forward(())
	}
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
	type Error = ();
	fn from_request(req: &'a Request<'r>) -> request::Outcome<User, ()> {
		let session = Session::from_request(req);
		let state = State::<HomeState>::from_request(req);
		if let (Outcome::Success(session), Outcome::Success(state)) = (session, state) {
			if let Some(user) = state.users.get(session.user_index) {
				return Outcome::Success(user.clone());
			}
		}
		Outcome::Forward(())
	}
}

struct CsrfValidation;

impl<'a, 'r> FromRequest<'a, 'r> for CsrfValidation {
	type Error = ();
	fn from_request(req: &'a Request<'r>) -> request::Outcome<CsrfValidation, ()> {
		// check for same origin, that host matches
		let target_origin = req.headers().get_one("Host").unwrap_or("");
		let source_origin = req.headers().get_one("Origin").unwrap_or(
								req.headers().get_one("Referer").unwrap_or(""));
		let source_origin = source_origin.split('/').nth(2).unwrap_or(""); // (https:)/()/(acshi.duckdns.org)/()
		if target_origin == "" || target_origin != source_origin {
			println!("Failed same origin policy. {} != {}", source_origin, target_origin);
			return Outcome::Forward(());
		}

		// same origin... check CSRF token as well
		let header_csrf = req.headers().get_one("X-CSRFToken").unwrap_or("");
		let mut header_csrf_key = [0u8; 32];
		if read_hex_str(header_csrf, &mut header_csrf_key).is_ok() {
			if let Outcome::Success(session) = Session::from_request(req) {
				if header_csrf_key == session.csrf {
					return Outcome::Success(CsrfValidation);
				}
			}
		}
		Outcome::Forward(())
	}
}

fn make_data(state: &HomeState, session: &Session, user: &User) -> TemplateData {
	let mut bool_ir_device_data = Vec::new();
	for d in &state.bool_ir_devices {
		let value = *d.value.lock().unwrap();
		bool_ir_device_data.push(BoolIrDeviceData { id: d.id, name: d.name.to_owned(), value });
	}
	TemplateData {
		username: user.username.to_owned(),
		csrf: buffer_to_hex_str(&session.csrf),
		bool_ir_devices: bool_ir_device_data,
	}
}

#[error(403)]
fn forbidden() -> &'static str {
	"<html>403 Forbidden</html>"
}

fn buffer_to_hex_str(buffer: &[u8]) -> String {
	let mut string = String::from("");
	for b in buffer {
		string.push_str(&format!("{:02x}", b));
	}
	return string;
}

fn make_session_key() -> [u8; 32] {
	let mut crypt_rng = OsRng::new().unwrap();
	let mut key = [0u8; 32];
	crypt_rng.fill_bytes(&mut key);
	key
}

#[derive(FromForm)]
struct LoginAttempt {
    username: String,
    password: String,
	remember_me: bool,
}

#[post("/login", data = "<login_attempt>")]
fn login(login_attempt: Form<LoginAttempt>, state: State<HomeState>, mut cookies: Cookies) -> Redirect {
	let login_attempt = login_attempt.into_inner();
	let username = &login_attempt.username;
	let password = &login_attempt.password;
	let remember_me = login_attempt.remember_me;

	let users = &state.users;
	let user = user_for_name(&users, &username);

	// compute hash before redirecting on bad username to help against timing attack
	// since the hash computation is fairly slow
	let params = &state.scrypt_params;
	let sparams = scrypt::ScryptParams::new(params.log_n, params.r, params.p);
	let mut hash = [0u8; 32];
	if user.is_none() {
		scrypt::scrypt(password.as_bytes(), &[0u8; 16], &sparams, &mut hash);
		return Redirect::to("/login_failed");
	} else {
		scrypt::scrypt(password.as_bytes(), &user.unwrap().salt, &sparams, &mut hash);
	}
	let user = user.unwrap();

	println!("computed hash\t [{}]", buffer_to_hex_str(&hash));
	println!("actual hash\t [{}]", buffer_to_hex_str(&user.hash));

	if hash == user.hash {
		let session_key = make_session_key();
		let key_str = buffer_to_hex_str(&session_key);
		let mut cookie_build = Cookie::build("session", key_str).http_only(true);
	    if remember_me {
			cookie_build = cookie_build.max_age(Duration::days(2));
		}
		cookies.add(cookie_build.finish());

		let expiration = Utc::now() + Duration::days(2);
		let csrf = make_session_key();
		let mut sessions = state.sessions.lock().unwrap();
		sessions.push(Session {key: session_key, user_index: user.user_index, expiration, csrf});
		return Redirect::to("/");
	}
	Redirect::to("/login_failed")
}

fn key_from_session_cookie(cookies: &Cookies) -> Option<[u8; 32]> {
	let cookie = cookies.get("session");
	if let Some(cookie) = cookie {
		let mut key = [0u8; 32];
		let key_str = cookie.value();
		match read_hex_str(key_str, &mut key) {
			Ok(_) => { return Some(key); },
			Err(_) => { return None; }
		}
	}
	None
}

#[get("/logout")]
fn logout(state: State<HomeState>, mut cookies: Cookies) -> Redirect {
	let key = key_from_session_cookie(&cookies);
	if let Some(key) = key {
		let mut sessions = state.sessions.lock().unwrap();
		let session_index = sessions.iter().position(|s| s.key == key);
		if let Some(session_index) = session_index {
			sessions.swap_remove(session_index);
		}
		cookies.remove(Cookie::named("session"));
	}
	Redirect::to("/")
}

#[get("/")]
fn admin_index(state: State<HomeState>, session: Session, user: User) -> Template {
	Template::render("admin_index", &make_data(&state, &session, &user))
}

#[get("/device_state")]
fn device_state(state: State<HomeState>, session: Session, user: User) -> Json<Value> {
	Json(json!(make_data(&state, &session, &user)))
}

#[get("/device_state", rank = 2)]
fn device_state_unauthorized() -> Redirect {
	Redirect::to("/")
}

#[put("/device_state/<id>/<value>")]
fn set_device_state(id: u16, value: bool, state: State<HomeState>, session: Session, user: User, _csrf: CsrfValidation) -> Json<Value> {
	for d in &state.bool_ir_devices {
		if d.id == id {
			*d.value.lock().unwrap() = value;
			break;
		}
	}
	Json(json!(make_data(&state, &session, &user)))
}

// #[options("/device_state/<_id>/<_value>")]
// fn set_device_state_options(_id: u16, _value: bool) -> Response<'static> {
// 	Response::build().raw_header("Allow", "PUT")
// 					 .raw_header("Access-Control-Allow-Origin", "http://localhost.test:9000")
// 					 .raw_header("Access-Control-Allow-Methods", "PUT")
// 					 .finalize()
// }

#[get("/test")]
fn test(state: State<HomeState>) -> Template {
	Template::render("admin_index", &make_data(&state,
		&Session {
			key: [0u8; 32],
			user_index: 42,
			expiration: Utc::now(),
			csrf: [0u8; 32],
		},
		&User {
			username: String::from("test_man"),
			user_index: 42,
			salt: [0u8; 16],
			hash: [0u8; 32]
		}))
}

#[get("/login_failed")]
fn login_failed() -> Template {
	Template::render("login", hashmap!{"login_failed" => true})
}

#[get("/", rank = 2)]
fn login_form() -> Template {
	Template::render("login", ())
}

#[error(404)]
fn not_found() -> Template {
	Template::render("404", ())
}

#[get("/resources/<file..>")]
fn resources(file: PathBuf) -> Option<NamedFile> {
	NamedFile::open(Path::new("resources/").join(file)).ok()
}

fn read_hex_str(hex_str: &str, output: &mut [u8]) -> Result<(), String> {
	if hex_str.len() != 2 * output.len() {
		return Err(format!("Error hex string '{}' does not have {} bytes of hex", hex_str, output.len()));
	}
	for i in 0..output.len() {
		output[i] = u8::from_str_radix(&hex_str[i*2..i*2+2], 16).unwrap();
	}
	Ok(())
}

fn parse_config() -> HomeState {
	let mut conf = config::Config::default();
	match conf.merge(config::File::with_name("settings")) {
		Ok(_) => (),
		Err(e) => {
			eprintln!("Error opening settings.toml file: {}", e);
			std::process::exit(-1);
		}
	}
	conf.set_default("scrypt.log_n", 15).unwrap();
	conf.set_default("scrypt.r", 8).unwrap();
	conf.set_default("scrypt.p", 1).unwrap();

	#[derive(Debug, Deserialize)]
	struct ConfUser {
		username: String,
		salt: String,
		hash: String,
	}

	#[derive(Debug, Deserialize)]
	pub struct ConfBoolIrDevice {
		id: u16,
		name: String,
	}

	#[derive(Debug, Deserialize)]
	struct ConfSettings {
		ir_key: String,
		users: Vec<ConfUser>,
		scrypt: ScryptParams,
		bool_ir_devices: Vec<ConfBoolIrDevice>,
	}

	let settings: ConfSettings = match conf.try_into() {
		Ok(settings) => settings,
		Err(e) => {
			eprintln!("Configuration error in settings.toml file: {}", e);
			std::process::exit(-1);
		}
	};

	let mut users = Vec::new();
	let mut user_index = 0;
	for u in settings.users {
		let mut salt = [0u8; 16];
		let mut hash = [0u8; 32];
		read_hex_str(&u.salt, &mut salt[..]).unwrap();
		read_hex_str(&u.hash, &mut hash[..]).unwrap();
		users.push(User { username: u.username.to_owned(), user_index, salt, hash });
		user_index += 1;
	}

	let mut bool_ir_devices = Vec::new();
	for d in settings.bool_ir_devices {
		bool_ir_devices.push(BoolIrDevice { value: Mutex::new(false), id: d.id, name: d.name.to_owned() });
	}

	let mut ir_key = [0u8; 32];
	read_hex_str(&settings.ir_key, &mut ir_key[..]).unwrap();

	let sessions = Mutex::new(Vec::<Session>::new());
	HomeState {scrypt_params: settings.scrypt, users, sessions, ir_key, bool_ir_devices}
}

fn main() {
	let state = parse_config();

	rocket::ignite()
		.manage(state)
		.mount("/", routes![resources, admin_index, device_state, device_state_unauthorized, set_device_state, login_form, login_failed, login, logout, test])
		.catch(errors![not_found, forbidden])
		.attach(Template::fairing())
		.launch();
}
