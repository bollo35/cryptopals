extern crate ooga;
use ooga::cipher_utils::{cbc_encrypt, cbc_decrypt};
use ooga::byte_utils::xor;

extern crate rand;
use rand::Rng;

use std::string::FromUtf8Error;

fn main() {
	// generate a random AES key
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();

	let input = b"AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAA";
	let ciphertext = user_input(&input[..], &key);
	let mut new_ct = Vec::with_capacity(48);// 3 blocks of ciphertext
	new_ct.extend_from_slice(&ciphertext[..16]);
	new_ct.append(&mut vec![0; 16]);
	new_ct.extend_from_slice(&ciphertext[..16]);
	new_ct.extend_from_slice(&ciphertext[48..]);
	let decryption = decrypt_url(&new_ct, &key);
	match decryption {
		Ok(pt) => println!("Plaintext: {}", pt),
		Err(utf8err) => {
			let dec = utf8err.into_bytes();
			let block1 = &dec[..16];
			let block3 = &dec[32..];
			let rec_key = xor(block1, block3);
			println!("recovered key: {:?}", rec_key);
			println!("recovered key == original key? {}", rec_key == key);
		},
	}
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

	let iv = vec![0; key.len()];
	cbc_encrypt(key, &iv, to_enc.as_slice())
}

fn decrypt_url(ciphertext: &[u8], key: &[u8]) -> Result<String, FromUtf8Error> {
	let iv = key.clone(); //vec![0; key.len()];
	let decrypted = cbc_decrypt(key, &iv, ciphertext).unwrap();
	String::from_utf8(decrypted)
}
