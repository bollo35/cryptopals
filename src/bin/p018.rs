extern crate ooga;
use ooga::cipher_utils::ctr_stream;
use ooga::byte_utils::xor;
use ooga::base64;

fn main() {
	let block_size = 16;
	let input = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
	let ciphertext = base64::decode(&input);
	// round up
	let num_blocks = (ciphertext.len() + block_size)/block_size;
	let nonce = [0u8; 8];
	let stream = ctr_stream(b"YELLOW SUBMARINE", &nonce, num_blocks as usize);

	let dec = xor(&ciphertext[..], &stream);
	println!("plaintext: {}", String::from_utf8(dec).unwrap());
}
