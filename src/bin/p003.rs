extern crate ooga;
use ooga::byte_utils::ToByteVector;
use ooga::stat_utils::{rank_1byte_xor};

fn main() {
	let enc = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_byte_vec();
	let candidates = rank_1byte_xor(&enc, false);
	for c in candidates.iter() {
		println!("[{}] ({}) => {:?}",c.key, c.score, c.plaintext);
	}
}
