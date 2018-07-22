extern crate ooga;
use ooga::base64;
use ooga::cipher_utils::{ecb_decrypt, ctr_stream};
use ooga::byte_utils::xor;

use std::fs::File;
use std::io::Read;

extern crate rand;
use rand::Rng;

fn main() {
	let mut f = File::open("25.txt").expect("Unable to open '25.txt'");
	let mut contents = String::new();
	f.read_to_string(&mut contents).expect("Trouble reading'25.txt'");

	let b64txt = contents.lines().collect::<String>();
	let ciphertext = base64::decode(&b64txt);
	let plaintext = ecb_decrypt(b"YELLOW SUBMARINE", None, &ciphertext);
	
	// generate a random key
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();
	
	let num_blocks = plaintext.len() / 16 + if plaintext.len() % 16 > 0 { 1 } else { 0 };
	let nonce = [0u8;8];
	let stream = ctr_stream(&key, &nonce, num_blocks as usize);

	let mut ciphertext = xor(&plaintext[..], &stream);
	let newtext = vec![0; ciphertext.len()];
	let ct_clone = ciphertext.clone();
	edit(& mut ciphertext, &key, 0, &newtext);
	let pt = xor(&ct_clone, &ciphertext);
	println!("Recovered plaintext:\n{}", String::from_utf8(pt).unwrap());
}

fn edit(ciphertext: &mut [u8], key: &[u8], offset: usize, newtext: &[u8]) {
	assert!(offset + newtext.len() <= ciphertext.len());
	let num_blocks = ciphertext.len() / 16 + if ciphertext.len() % 16 > 0 { 1 } else { 0 };
	let nonce = [0u8;8];
	let stream = ctr_stream(key, &nonce, num_blocks as usize);
	let new_ct = xor(newtext, &stream[offset..]);

	// do we alter the actual ciphertext?
	// yes!
	for (ct, nct) in ciphertext[offset..].iter_mut().zip(new_ct.iter()) {
		*ct = *nct;
	}
}
