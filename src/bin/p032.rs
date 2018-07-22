#![feature(plugin)]
#![feature(custom_derive)]
#![feature(duration_extras)]
#![plugin(rocket_codegen)]

extern crate ooga;
use ooga::sha1::sha1;
use ooga::byte_utils::{ToByteVector, ToHexString, xor};

extern crate rocket;
use rocket::{State, local::Client};

extern crate rand;
use rand::Rng;

use std::{thread, time};
use std::time::SystemTime;


#[get("/")]
fn index() -> &'static str {
	"Hello, world!"
}

#[derive(FromForm)]
struct FileCheck {
	file: String,
	signature: String,
}

const DELAY: u32 = 3;

#[get("/test?<file_check>")]
fn test(key: State<Key>, file_check: FileCheck) -> String {
	if file_check.signature.len() % 2 != 0 {
		return "Internal server error".to_string();
	} 
	
	let msg = file_check.file.as_bytes();
	// calculate the HMAC of the file name
	let hm = hmac(&key.key[..], &msg[..]);

	// convert the HMAC-SHA1 into a byte vector
	let hm = hm.to_byte_vec();
	let submitted = file_check.signature.to_byte_vec();

	let matches = insecure_compare(&submitted, &hm);

	if matches {
		"Ok".to_string()
	} else {
		"Internal server error".to_string()
	}
}

fn insecure_compare(s1: &[u8], s2: &[u8]) -> bool {
	let delay = time::Duration::from_millis(DELAY as u64);
	for (a, b) in s1.iter().zip(s2.iter()) {
		if a != b { return false; }
		thread::sleep(delay);
	}
	true
}

// HMAC-SHA1
fn hmac(key: &[u8], msg: &[u8]) -> String {
	let block_size = 64usize;
	let mut hkey = if key.len() > block_size {
		sha1(key.to_vec()).to_byte_vec()
	} else {
		key.clone().to_vec()
	};

	while hkey.len() < block_size {
		hkey.push(0u8);
	}

	let mut okey = xor(&hkey, &vec![0x5c; block_size]); 
	let mut ikey = xor(&hkey, &vec![0x36; block_size]); 

	ikey.extend_from_slice(msg);
	let mut ihash = sha1(ikey).to_byte_vec();
	okey.append(&mut ihash);
	sha1(okey).to_hex_string()
}

struct Key {
	key: Vec<u8>,
}

fn main() {
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(64).collect::<Vec<u8>>();
	let rocket = rocket::ignite()
		.manage(Key { key: key })
		.mount("/", routes![index, test]);

	let client = Client::new(rocket).unwrap();
	let mut hash : [u8; 20] = [0u8; 20];
	let mut bytes_correct = 0;
	let guesses = 5;
	'outer: loop {
		// guess the byte 10 times before accepting it as correct
		let mut num_right = vec![0; guesses];
		for i in 0..guesses {
			let req_time = SystemTime::now();
			let route = format!("/test?file=foo&signature={}", hash.to_hex_string());
			let mut response = client.get(route).dispatch();
			match req_time.elapsed() {
				Ok(elapsed) => {
					let body = response.body_string().unwrap();	
					if body != "Ok" {
						let bytes_right	= (elapsed.as_secs() as u32/(1000/DELAY)) + elapsed.subsec_millis() / DELAY;
						num_right[i] = bytes_right;
					} else { 
						break 'outer; 
					}
				}
				Err(e) => println!("Error: {:?}", e),
			};
		}
		num_right.sort();
		// take the pessimistic view
		let bytes_right = num_right[0];

		if bytes_right > bytes_correct {
			bytes_correct = bytes_right;
		} else {
			hash[bytes_correct as usize] += 1;
		}
	}

	println!("The hash is: {}", hash.to_hex_string());
}
