#![feature(iterator_step_by)]
extern crate ooga;
use ooga::base64;
use ooga::stat_utils;
use ooga::byte_utils::{repeated_xor_enc};

use std::fs::File;
use std::io::Read;

struct CandidateKeySize {
	pub len: usize,
	pub norm_ham_dist: f64,
}


impl CandidateKeySize {
	pub fn new(len: usize, norm_ham_dist: f64) -> Self {
		CandidateKeySize { len: len, norm_ham_dist: norm_ham_dist }
	}
}

// assumes both byte strings are of the same length
fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
	let mut counter = 0;
	for (a, b) in a.iter().zip(b.iter()) {
		let mut xor = a ^ b;
		for _ in 0..8 { 
			counter += (xor & 1) as usize;
			xor >>= 1;
		}
	}
	counter
}
fn main() {
	let mut f = File::open("6.txt").expect("Unable to open '6.txt'");
	let mut contents = String::new();
	f.read_to_string(&mut contents).expect("Trouble reading '6.txt'");

	let b64encoded = contents.lines().collect::<String>();
	let ciphertext = base64::decode(&b64encoded);

	let max_key_size = 40; // max guess for the key size
	let mut candidate_key_sizes = Vec::with_capacity(max_key_size);

	for key_size in 2..max_key_size+1 {
		// compute a normalized hamming distance between a few blocks of length key_size
		// specifically, get the hamming distance with each block and it's neighbor
		let num_blocks = ciphertext.len() / key_size;
		let mut cumulative_ham_dist = 0;

		for i in 0..num_blocks-1 {
			let a = (i*key_size)..( (i+1) * key_size );
			let b = ( (i+1) * key_size ) .. ( (i+2) * key_size );
			cumulative_ham_dist += hamming_distance(&ciphertext[a], &ciphertext[b]);
		}

		let norm_ham_dist = cumulative_ham_dist as f64 / (key_size * (num_blocks - 1)) as f64;
		candidate_key_sizes.push(CandidateKeySize::new(key_size, norm_ham_dist));
	}

	// sort the candidates by hamming distance
	candidate_key_sizes.sort_by(|a, b| a.norm_ham_dist.partial_cmp(&b.norm_ham_dist).unwrap());

	// only try the top 6
	let mut keys_to_try = Vec::with_capacity(candidate_key_sizes.len());
	for candidate in candidate_key_sizes.iter().take(6) {
		let guessed_len = candidate.len;
		let mut key_guesses = Vec::new();

		for i in 0..guessed_len {
			let stream = ciphertext.iter().skip(i).step_by(guessed_len).map(|&x| x).collect::<Vec<u8>>();
			let possible_keys = stat_utils::rank_1byte_xor(&stream, false);

			// don't waste time on a fruitless endeavor
			if possible_keys.len() == 0 { break; }

			key_guesses.push(possible_keys);
		}

		if key_guesses.len() == guessed_len {
			// print out the top 3 candidates
			let key = key_guesses.iter().map(|guess| guess[0].key).collect::<Vec<u8>>();
			keys_to_try.push(key.clone());
			let key = key.iter().map(|&c| c as char).collect::<String>();
			println!("Possible key of length {}:\n\t{}", guessed_len, key);
		}
	}

	println!();
	println!();
	for key in keys_to_try.iter() {
		let dec = repeated_xor_enc(&ciphertext, &key[..]);
		println!("key: {:?}", String::from_utf8(key.clone()).unwrap());
		println!();
		println!("{}", String::from_utf8(dec).unwrap());
	}
}
