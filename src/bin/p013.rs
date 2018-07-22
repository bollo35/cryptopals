extern crate rand;
use rand::Rng;
extern crate ooga;
use ooga::cipher_utils::{ecb_encrypt, ecb_decrypt};

fn main() {
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();

	// construct the following string to encrypt
	// 1234567890admin\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb@yay.com
	//           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ -> This is a pkcs7 padded block
	// we want to put this at the end of our encrypted fake profile message
	let first_input = "1234567890admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b@yay.com";
	
	// we want to save the 2nd block output by this
	let enc_profile  = encrypt_profile(&key, first_input);
	let admin_block = &enc_profile[16..32];

	// now we construct another input to make the profile that we want
	// line it up nicely so the padding is a full block of 16s
	let email_input = "pwn@yahoo.com";
	let mut ct = encrypt_profile(&key, email_input);
	// chop off our last block - since we lined up everything nicely
	let len = ct.len();
	ct.truncate(len - 16);
	ct.extend_from_slice(admin_block);

	let dec = decrypt_profile(&key, &ct);
	println!("decryption: {:?}", String::from_utf8(dec).unwrap());
}

fn profile_for(email: &str) -> String {
	let sanitized_email = email.replacen("", "", email.len()).
	                            replacen("=","", email.len());
	format!("email={}&uid=10&role=user", sanitized_email)
}

fn encrypt_profile(key: &[u8], email: &str) -> Vec<u8> {
	let profile = profile_for(email);
	ecb_encrypt(key, None, profile.as_bytes())
}

fn decrypt_profile(key: &[u8], encrypted_profile: &[u8]) -> Vec<u8> {
	ecb_decrypt(key, None, encrypted_profile)
}
