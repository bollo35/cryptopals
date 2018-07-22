extern crate ooga;
use ooga::cipher_utils::{cbc_encrypt, ecb_encrypt, EncryptionScheme, detect_encryption_scheme};
extern crate rand;
use rand::{Rng};

fn main() {
	// use 3 blocks worth of input will be sufficient to get a repeated block
	let input = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec();
	let (answer, enc) = encryption_oracle(input);
	let detected_scheme = detect_encryption_scheme(&enc);
	println!("Actual scheme: {:?}, Detected Scheme: {:?}", answer, detected_scheme);
}

fn encryption_oracle(mut input: Vec<u8>) -> (EncryptionScheme, Vec<u8>) {
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();

	// generate random pre-padding
	let prepad_len = rng.gen_range::<usize>(5,10);
	let mut prepad = rng.gen_iter::<u8>().take(prepad_len).collect::<Vec<u8>>();

	// generate random post-padding
	let postpad_len = rng.gen_range::<usize>(5, 10);
	let mut postpad = rng.gen_iter::<u8>().take(postpad_len).collect::<Vec<u8>>();

	// smash all the stuff together
	prepad.append(&mut input);
	prepad.append(&mut postpad);

	let plaintext = prepad;

	// encrypt using cbc or ecb at random
	if rng.gen() { // CBC Encryption
		let iv = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();
		(EncryptionScheme::CBC, cbc_encrypt(&key, &iv, &plaintext))
	} else { // ECB encryption
		let ct = ecb_encrypt(&key, None, &plaintext[..]);
		(EncryptionScheme::ECB, ct)
	}
}
