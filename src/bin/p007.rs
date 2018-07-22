extern crate ooga;
use ooga::base64;

extern crate openssl;
use openssl::symm::{Cipher, decrypt};

use std::fs::File;
use std::io::Read;

fn main() {
	let mut f = File::open("7.txt").expect("Unable to open '7.txt'");
	let mut contents = String::new();
	f.read_to_string(&mut contents).expect("Trouble reading '7.txt'");


	let contents = contents.lines().collect::<String>();
	let ciphertext = base64::decode(&contents);

	let cipher = Cipher::aes_128_ecb();
	let key = b"YELLOW SUBMARINE";

	let plaintext = decrypt (
	    cipher,	
	    key,
	    None, // no initialization vector
	    &ciphertext[..]).unwrap();

	println!("{}", String::from_utf8(plaintext).unwrap());
}
