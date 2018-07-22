extern crate ooga;
use ooga::mtwister::MT19937;
use ooga::byte_utils::xor;

extern crate rand;
use rand::Rng;
use rand::distributions::{Range, Sample};

use std::time::{SystemTime, UNIX_EPOCH};
use std::mem;

fn main() {
	let mut rng = rand::thread_rng();
	let num_chars = Range::new(0usize, 60).sample(&mut rng);
	let mut s : String = rng.gen_ascii_chars().take(num_chars).collect();
	s.push_str("AAAAAAAAAAAAAA");

	let original_key = rng.gen();
	let keystream = ctr_stream(original_key, s.len());
	let enc = xor(s.as_bytes(), &keystream);

	// recover the key
	let mut recovered_key : Option<u16> = None;
	for key in 0..65536usize {
		let keystream = ctr_stream(key as u16, s.len());
		let dec = xor(&enc, &keystream);
		let mut found_key = true;
		for pt in dec[dec.len()-14..].iter() {
			found_key &= *pt == b'A';
		}
		if found_key {
			recovered_key = Some(key as u16);
			break;
		}
	}

	println!("recovered key: {} == original_key: {} ? {}", recovered_key.unwrap(), original_key, original_key == recovered_key.unwrap());
	
	//password reset token...
	// not sure if i understand this one, it seems redundant/silly?
	let systime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
	let seed = (systime & 0x00000000FFFFFFFF) as u32;
	let reset_token = ctr_stream32(seed, 25);
	println!("Is it a m19937 token based on \"current\" time? {:?}", is_mt19937_token(&reset_token));
}

fn is_mt19937_token(token: &[u8]) -> Option<u32> {
	let thirtyseconds_ago = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 30; //now - 30seconds
	let token_len = token.len();
	for time in thirtyseconds_ago..(thirtyseconds_ago+31) {
		let seed = (time & 0x00000000FFFFFFFF) as u32;
		let test_stream = ctr_stream32(seed, token_len);
		if test_stream == token {
			return Some(seed);
		}
	}
	None
}

fn ctr_stream(key: u16, size: usize) -> Vec<u8> {
	let mut rng = MT19937::new(key as u32);
	let iters = size/4 + if size%4 > 0 { 1 } else {0};
	let mut outp = Vec::with_capacity(size);
	for _ in 0..iters {
		let bytes : [u8;4] = unsafe { mem::transmute(rng.next().to_le()) };
		outp.extend_from_slice(&bytes);
	}
	outp.truncate(size);
	outp
}

fn ctr_stream32(key: u32, size: usize) -> Vec<u8> {
	let mut rng = MT19937::new(key);
	let iters = size/4 + if size%4 > 0 { 1 } else {0};
	let mut outp = Vec::with_capacity(size);
	for _ in 0..iters {
		let bytes : [u8;4] = unsafe { mem::transmute(rng.next().to_le()) };
		outp.extend_from_slice(&bytes);
	}
	outp.truncate(size);
	outp
}
