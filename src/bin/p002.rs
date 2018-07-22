extern crate ooga;
use ooga::byte_utils::{ToByteVector, ToHexString, xor};

fn main() {
	let s1 = "1c0111001f010100061a024b53535009181c".to_byte_vec();
	let s2 = "686974207468652062756c6c277320657965".to_byte_vec();
	let expected = "746865206b696420646f6e277420706c6179";
	let xored = xor(&s1, &s2).to_hex_string();
	println!("xored: {}", xored);
	println!("Equal to expected? {}", xored == expected);
}
