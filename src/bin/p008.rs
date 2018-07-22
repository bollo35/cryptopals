use std::fs::File;
use std::io::Read;
use std::collections::HashSet;

fn main() {
	let mut f = File::open("8.txt").expect("Unable to open '8.txt'");
	let mut contents = String::new();
	f.read_to_string(&mut contents).expect("Trouble reading '8.txt'");

	let block_size = 2 * 16; // this is scaled for byte strings
	for line in contents.lines() {
		// detect ECB by looking for duplicate blocks
		// a block is 16 bytes, each byte requires 2 characters
		let num_blocks = line.len()/block_size;
		let mut hashset : HashSet<String> = HashSet::with_capacity(num_blocks);
		for i in 0..num_blocks {
			let block = line[i*block_size..(i+1)*block_size].to_string();
			if hashset.contains(&block) {
				// this is probably encrypted in ECB mode
				println!("Found ECB encrypted message:");
				println!("----------------------------");
				println!("{}", line);
				println!("----------------------------");
				println!("\nRepeated block: [{}]", block);
				break;
			}
			hashset.insert(block);
		}
	}
}
