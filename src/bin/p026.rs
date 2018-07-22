extern crate ooga;
use ooga::cipher_utils::ctr_stream;
use ooga::byte_utils::xor;

extern crate rand;
use rand::Rng;

fn main() {
	// generate a random key
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();

	let mut ciphertext = user_input(b":admin<true", &key);
	ciphertext[32] ^= 0x01;
	ciphertext[38] ^= 0x01;

	let success = dec_and_search(&ciphertext, &key);
	println!("Success? {}", success);
}

fn user_input(input: &[u8], key: &[u8]) -> Vec<u8> {
	let prefix = b"comment1=cooking%20MCs;userdata=";
	let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
	let mut to_enc = Vec::with_capacity(prefix.len() + input.len() + suffix.len());
	to_enc.extend_from_slice(&prefix[..]);
	// quote ';' and '=' characters
	for byte in input {
		if *byte == b';' || *byte == b'=' {
			to_enc.push(b'"');
			to_enc.push(*byte);
			to_enc.push(b'"');
		} else {
			to_enc.push(*byte);
		}
	}

	to_enc.extend_from_slice(&suffix[..]);

	let num_blocks = to_enc.len() / 16 + if to_enc.len() % 16 > 0 { 1 } else { 0 };
	let nonce = [0u8;8];
	let stream = ctr_stream(&key, &nonce, num_blocks as usize);
	xor(&to_enc, &stream)
}

fn dec_and_search(ciphertext: &[u8], key: &[u8]) -> bool {
	let num_blocks = (ciphertext.len() + 16) / 16;
	let nonce = [0u8;8];
	let stream = ctr_stream(&key, &nonce, num_blocks as usize);
	let decrypted = xor(&ciphertext, &stream);

	let string = String::from_utf8(decrypted).unwrap();
	string.contains(";admin=true;")
}
