extern crate ooga;
use ooga::byte_utils::ToByteVector;
use ooga::stat_utils::rank_1byte_xor;

use std::fs::File;
use std::io::Read;
use std::cmp::Ordering;

fn main() {
	let mut f = File::open("4.txt").expect("Unable to open '4.txt'");
	let mut s = String::with_capacity(327*60); // 327 60-character strings
	f.read_to_string(&mut s).expect("Trouble reading file contents.");

	let mut promising = Vec::new();
	for line in s.lines() {
		let bytes = line.to_byte_vec();
		let dec = rank_1byte_xor(&bytes, false);
		for d in dec {
			promising.push(d);
		}
	}

	// sort according to score
	promising.sort_by(|a,b| if a.score < b.score { Ordering::Less } else { Ordering::Equal }  );

	println!("Our {} candidates...", promising.len());
	for candidate in promising.iter() {
		println!("[{}] ({}) => {:?}", candidate.key, candidate.score, candidate.plaintext);
	}
}
