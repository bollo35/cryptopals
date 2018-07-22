extern crate ooga;
use ooga::base64;

extern crate openssl;
use openssl::symm::{encrypt, Cipher};

extern crate rand;
use rand::Rng;
use rand::distributions::{Uniform};

fn main() {
	let secret = base64::decode("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F");

	let range = Uniform::new_inclusive(0, 255u8);
	let encryption_oracle = move |request: &[u8]| -> Vec<u8> {
		let mut plaintext = Vec::with_capacity(request.len() + secret.len());
		plaintext.extend_from_slice(&request);
		plaintext.extend_from_slice(&secret);
		let key = rand::thread_rng().sample_iter(&range).take(16).collect::<Vec<u8>>();
		let enc = encrypt (
			Cipher::rc4(),
			&key,
			None,
			&plaintext).unwrap();
		enc
	};


	// 1. determine the length of the encrypted data
	let tmp = Vec::new();
	let ct = encryption_oracle(&tmp);
	let msg_len = ct.len();

	let mut plaintext = Vec::with_capacity(msg_len);

	// then use the biases to figure out the stuff
	// z16 = 240
	// z32 = 224
	// since we know the message length is 30, let's just push everything out to byte 32
	let mut map = [0usize; 256];
	// for each byte in the plaintext
	for index in 0..msg_len {
		// create dummy text to extend the byte out to the 32nd byte
		let prefix = vec![b'A'; 31 - index];
		// pick a number of queries to make...say 2**25?
		for _ in 0..(1<<25) {
			let ct = encryption_oracle(&prefix);
			map[ct[31] as usize] += 1;
		}
		
		let mut max = 0;
		let mut max_index = 0;
		for (i, val) in map.iter().enumerate() {
			if *val > max {
				max = *val;
				max_index = i as u8;
			}
		}

		// assume that the max_index is equivalent to 224 (since we used index 32)
		plaintext.push( max_index ^ 224 );
		println!("recovered char[{}]: {}", index, max_index ^ 224);
		// zero out the map and do it again!
		for v in map.iter_mut() {
			*v = 0;
		}
	}

	println!("Recovered plaintext? {:?}", String::from_utf8(plaintext));
}
