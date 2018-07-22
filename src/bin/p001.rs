extern crate ooga;
use ooga::base64;
use ooga::byte_utils::ToByteVector;

fn main() {
	let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	let byte_str = hex.to_byte_vec();
	let encoded = base64::encode(&byte_str);
	println!("Base64 encoded string: {}", encoded);
	println!("Equal to expected value? {}", encoded == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

}
