extern crate ooga;
use ooga::base64;
use ooga::cipher_utils::ctr_stream;
use ooga::stat_utils::rank_1byte_xor;
use ooga::byte_utils::xor;

use std::fs::File;
use std::io::Read;

extern crate rand;
use rand::Rng;

fn main() {
	let mut f = File::open("20.txt").expect("Unable to open '20.txt'");
	let mut contents = String::new();
	f.read_to_string(&mut contents).expect("Trouble reading '20.txt'");

	let mut plaintexts = contents.lines().map(|s| base64::decode(&s)).
	                              collect::<Vec<Vec<u8>>>();

	// sort plaintexts by length
	plaintexts.sort_by(|a, b| a.len().cmp(&b.len()));

	let len = plaintexts[0].len();

	// truncate all plaintexts to the same length
	for pt in plaintexts.iter_mut() {
		pt.truncate(len);
	}

	// round up
	let blocks = (len + 16)/ 16;
	let nonce = [0u8; 8];
	
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();

	let keystream = ctr_stream(&key, &nonce, blocks);
	let ciphertexts : Vec<Vec<u8>> = plaintexts.iter().map(|ref p| xor(&p, &keystream)).collect();

	// let's do this one byte at a time
	let mut key = Vec::with_capacity(len);
	for i in 0..len {
		let stream = ciphertexts.iter().map(|ct| ct[i]).collect::<Vec<u8>>();
		let key_candidates = rank_1byte_xor(&stream, i == 0);
		key.push( key_candidates[0].key);
	}

	// now try to decrypt all the ciphertexts
	for ct in ciphertexts {
		let pt = xor(&key, &ct);
		println!("{:?}", String::from_utf8(pt));
	}
}
