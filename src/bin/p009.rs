extern crate ooga;
use ooga::cipher_utils::pkcs7_padding;
fn main() {
	let block_len = 20;
	let block = b"YELLOW SUBMARINE".to_vec();
	println!("Padded block: {:?}", pkcs7_padding(block, block_len));
	
}
