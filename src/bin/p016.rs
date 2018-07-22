extern crate rand;
use rand::Rng;
extern crate ooga;
use ooga::cipher_utils::{cbc_encrypt, cbc_decrypt};

fn main() {
	// generate a random key
	let key = rand::thread_rng().gen_iter::<u8>().take(16).collect::<Vec<u8>>();

	//................::::::::::::::::................::::::::::::::::................::::::::::::::::
	//012345678901234567890123456789012345678901234567890123456789012345678901234567890
	//comment1=cooking%20MCs;userdata=woop;admin=true;comment2=%20like%20a%20pound%20of%20bacon
	//comment1=cooking%20MCs;userdata=woop:admin<true;comment2=%20like%20a%20pound%20of%20bacon

	let mut enc = encrypt_msg("woop:admin<true", &key);

	// flip bits 5 and 11 in block 2
	enc[16 + 4]  ^= 1;
	enc[16 + 10] ^= 1;

	println!("User is admin? {}", is_admin(&key, &enc));
}

fn encrypt_msg(input: &str, key: &[u8]) -> Vec<u8> {
	//             01234567890123456789012345678901
	let prefix = b"comment1=cooking%20MCs;userdata=";
	//              012345678901234567890123456789012345678901
	let postfix = b";comment2=%20like%20a%20pound%20of%20bacon";
	let inp = input.replace("=","").replace(";", "");
	let mut full_input = Vec::with_capacity(prefix.len() + postfix.len() + input.len());
	full_input.extend_from_slice(&prefix[..]);
	full_input.extend_from_slice(inp.as_bytes());
	full_input.extend_from_slice(&postfix[..]);
	let iv = vec![0u8; 16];
	cbc_encrypt(key, &iv, &full_input[..])
}

fn is_admin(key: &[u8], data: &[u8]) -> bool {
	let iv = vec![0u8; 16];
	let dec = unsafe { String::from_utf8_unchecked(cbc_decrypt(key, &iv, data).unwrap())};
	dec.contains(";admin=true;")
}
