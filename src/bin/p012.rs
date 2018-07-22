extern crate ooga;
use ooga::base64;
use ooga::cipher_utils::{ecb_encrypt, detect_encryption_scheme};
extern crate rand;
use rand::Rng;
use std::collections::HashMap;


fn main() {
	let oracle = create_oracle();

	// (1) discover the block size...
	// discover the block size by increasing the input until the output length jumps in size
	let mut input = Vec::with_capacity(16);
	input.clear();
	let len_without_input = oracle(&input).len();
	let mut next_len = len_without_input;
	while next_len == len_without_input {
		input.push(b'A');
		next_len = oracle(&input).len();
	}

	let block_len = next_len - len_without_input;
	println!("Block length: {}", block_len);
	println!();

	// (2) determine the cipher mode
	let input = vec![b'A'; 48];
	let cipher_mode = detect_encryption_scheme(&oracle(&input));
	println!("Cipher mode: {:?}", cipher_mode);
	println!();


	let mut possible_chars : Vec<u8> = (32..127u8).map(|i| i).collect();
	possible_chars.push(b'\n');
	possible_chars.push(b'\r');

	let mut decryption = String::with_capacity(len_without_input);
	
	let blocks = len_without_input / block_len;
	// (3) make a block one byte short of the full block length
	//     except that's not exactly what I did here...
	let mut input = vec![b'A'; blocks*block_len];

	let last_block_start = input.len() - block_len;
	let last_block_end = input.len();
	let mut still_decrypting = true;
	while still_decrypting {
		// (4) create a dictionary - not sure if this is what they had in mind...
		let mut hashmap = HashMap::with_capacity(possible_chars.len());
		
		for c in possible_chars.iter() {
			input[last_block_end - 1] = *c;
			let enc = oracle(&input);
			hashmap.insert(enc[last_block_start..last_block_end].to_vec(),
			               input[last_block_start..last_block_end].to_vec());
		}
		// (5) make the magic happen
		// subtract one because we need an empty slot for the next byte
		let stop = input.len() - decryption.len() - 1; 
		let enc = oracle(&input[..stop]);

		let key = &enc[last_block_start..last_block_end];
		if let Some(dec) = hashmap.get(key) {
			let next_char = dec[block_len-1];
			decryption.push(next_char as char);
			input[last_block_end-1] = next_char;
			input.rotate_left(1);
		} else {
			still_decrypting = false;
		}
	}

	println!("Decryption:\n\n{}", decryption);
}

fn create_oracle() -> Box< Fn(&[u8]) -> Vec<u8>> {
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();
	let secret_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

	let decoded = base64::decode(&secret_string);

	let oracle = Box::new(move |input: &[u8]| {
		let mut full_msg = Vec::with_capacity(input.len() + decoded.len());
		full_msg.extend_from_slice(&input[..]);
		full_msg.extend_from_slice(&decoded[..]);
		ecb_encrypt(&key[..], None, &full_msg[..])
	});

	oracle
}
