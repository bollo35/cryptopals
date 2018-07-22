extern crate ooga;
use ooga::cipher_utils::{cbc_decrypt};
use ooga::base64;

use std::fs::File;
use std::io::Read;

fn main() {
	let mut f = File::open("10.txt").expect("Unable to open '10.txt'");
	let mut contents = String::new();
	f.read_to_string(&mut contents).expect("Trouble reading '10.txt'");

	let contents = contents.lines().collect::<String>();
	let ciphertext = base64::decode(&contents);

	let key = b"YELLOW SUBMARINE";
	let iv = vec![0u8; 16];

	let raw = cbc_decrypt(&key[..], &iv[..], &ciphertext[..]).unwrap();
	let plaintext = String::from_utf8(raw).unwrap();
	println!("{}", plaintext);
}
