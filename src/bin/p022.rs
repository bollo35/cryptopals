extern crate ooga;
use ooga::mtwister::MT19937;
use std::time::{self, SystemTime, UNIX_EPOCH};
use std::thread;

extern crate rand;
use rand::distributions::{Range, Sample};

fn main() {
	let rand_out = randu32();
	println!("Random output: {}", rand_out);
	// try to recover the seed
	// the maximum time it takes for us to get the random value is 2000 seconds
	// we just need to try to generate all the outputs from all those timestamps
	// until we get the answer we're interested in
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
	let then = now - 2003;
	for i in then..now {
		let seed = (i & 0x00000000FFFFFFFF) as u32;
		let mut rng = MT19937::new(seed);
		let rn = rng.next();
		if rn == rand_out {
			println!("Found the seed: {}", seed);
			break;
		}
	}
}

fn randu32() -> u32 {
	let mut rng = rand::thread_rng();
	let mut range = Range::new(40, 1000);
	let rand_wait = range.sample(&mut rng);
	thread::sleep(time::Duration::from_secs(rand_wait));
	let systime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
	let mut rng = MT19937::new((systime & 0x00000000FFFFFFFF) as u32);//systime.elapsed().unwrap().as_secs());
	thread::sleep(time::Duration::from_secs(rand_wait));
	rng.next()
}
