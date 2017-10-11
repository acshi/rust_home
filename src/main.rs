extern crate rand;
extern crate iron;
extern crate urlencoded;
extern crate router;

use iron::prelude::*;
use iron::status;
use iron::headers::ContentType;
use urlencoded::UrlEncodedQuery;
use router::Router;
use rand::{Rng, OsRng};

fn login(req: &mut Request) -> IronResult<Response> {
	let mut crypt_rng = OsRng::new().unwrap();
	println!("Random u32: {}", crypt_rng.next_u32());

	match req.get_ref::<UrlEncodedQuery>() {
        Ok(ref hashmap) => {
			if hashmap.contains_key("username") && hashmap.contains_key("password") {
				return Ok(Response::with((status::Ok, ContentType::html().0, "<html>Yay, logged in!</html>")))
			}
		},
        Err(_) => ()
    };
	return Ok(Response::with((status::Forbidden, ContentType::html().0, "<html>403 Forbidden</html>")));
}

fn index(_: &mut Request) -> IronResult<Response> {
	return Ok(Response::with((status::Ok, ContentType::html().0, "<html>Hello, World!</html>")));
}

fn not_found(_: &mut Request) -> IronResult<Response> {
	return Ok(Response::with((status::NotFound, ContentType::html().0, "<html>404 Not Found</html>")));
}

fn main() {
	let mut router = Router::new();
	router.get("/", index, "index");
	router.get("/login", login, "login");
	router.get("*", not_found, "not_found");
	Iron::new(router).http("127.0.0.1:9000").unwrap();
}
