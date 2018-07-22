extern crate ooga;
use ooga::cipher_utils::pkcs7_remove;

fn main() {
	println!("result: {:?}", pkcs7_remove(b"ICE ICE BABY\x04\x04\x04\x04"));
	println!("result: {:?}", pkcs7_remove(b"ICE ICE BABY\x05\x05\x05\x05"));
	println!("result: {:?}", pkcs7_remove(b"ICE ICE BABY\x01\x02\x03\x04"));
}
