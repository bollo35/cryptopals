extern crate ooga;
use ooga::mtwister::MT19937;
use std::time::{SystemTime, UNIX_EPOCH};

const N : usize = 624;
fn untemper_mt19937(outp: u32) -> u32 {
	let mut j = outp;
	// undo step 4
	j ^= j >> 18;

	// undo step 3
	j ^= (j << 15) & 0xefc60000;

	// undo step 2
	let og_mask = 0x9d2c5680;
	let mut mask_window = 0xFFFFFFE0;
	let mut rec = j & (!mask_window);
	while mask_window != 0 {
		let jp = j ^ ( (rec << 7) & og_mask );
		mask_window <<= 7;
		rec = jp & (!mask_window);
	}
	j = rec;

	// undo step 1
	mask_window = 0xFFE0_0000;
	rec = j & mask_window;
	while mask_window != 0 {
		let jp = j ^ (rec >> 11);
		mask_window >>= 11;
		rec |= jp & mask_window;
	}

	// recovered value from buffer
	rec
}

fn main() {
	let systime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
	let seed = (systime & 0x00000000FFFFFFFF) as u32;
	let mut rng = MT19937::new(seed);
	
	let mut shr = Vec::with_capacity(N);
	for _ in 0..N {
		shr.push(untemper_mt19937(rng.next()));
	}

	let mut rng_clone = MT19937::from_vec(shr);
	
	for _ in 0..10 {
		println!("OG: {} | CLONE: {}", rng.next(), rng_clone.next());
	}
}
