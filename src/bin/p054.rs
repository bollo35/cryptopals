extern crate rand;

use std::collections::HashMap;

use rand::Rng;
use rand::distributions::{Distribution, Uniform};
use std::mem;
use std::rc::Rc;
use std::sync::Mutex;

fn f(x: u32, y: u32, z: u32) -> u32 {
	(x & y) | (!x & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
	(x & y) | (x & z) | (y & z)
}

fn h(x: u32, y: u32, z: u32) -> u32 {
	x ^ y ^ z
}

fn round1(a: u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) -> u32 {
	a.wrapping_add( f(b, c, d) ).wrapping_add(x_k).rotate_left(s)
}

fn round2(a: u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) -> u32 {
	a.wrapping_add( g(b, c, d) ).wrapping_add(x_k).wrapping_add(0x5a827999).rotate_left(s)
}

fn round3(a: u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) -> u32 {
	a.wrapping_add( h(b, c, d) ).wrapping_add(x_k).wrapping_add( 0x6ed9eba1).rotate_left(s)
}

fn gen_padding_block(num_blocks: usize) -> Vec<u8> {
	let l = num_blocks * 512; // 512 bits/block
	let mut padding = Vec::with_capacity(64);
	padding.push(0x80);
	
	let k = 448usize.wrapping_sub(l % 512).wrapping_sub(8) % 512;
	let bytes = k / 8 + if k%8 > 0 { 1 } else { 0 };
	padding.append(&mut vec![0; bytes]);

	let len64b = unsafe { mem::transmute::<u64, [u8; 8]>( (l as u64).to_le()) };
	padding.extend_from_slice(&len64b);

	padding
}

fn bytes_to_u32s(msg: Vec<u8>) -> Vec<u32> {
	assert!(msg.len() % 16 == 0);
	msg.chunks(4).fold(Vec::with_capacity(msg.len()/4 + 1), | mut acc, curr | { 
		let data = unsafe {mem::transmute::<[u8; 4],u32>([curr[0], curr[1], curr[2], curr[3]])};
		acc.push(data.to_le());
		acc
	})
}

pub fn md4lite(msg: &[u32]) -> u32 {
	let mut h: u32 = 0x67452301;
	for chunk in msg.chunks(16) {
		h = hashfn(chunk, h);
	}
	h
}

pub fn hashfn(m: &[u32], h: u32) -> u32 {
	let mut a = h;
	let mut b = 0;
	let mut c = 0;
	let mut d = 0;

	let aa = a;
	let bb = b;
	let cc = c;
	let dd = d;

	// ROUND 1!
	a = round1(a, b, c, d, m[0] , 3);
	d = round1(d, a, b, c, m[1] , 7);
	c = round1(c, d, a, b, m[2] , 11);
	b = round1(b, c, d, a, m[3] , 19);
	a = round1(a, b, c, d, m[4] , 3);
	d = round1(d, a, b, c, m[5] , 7);
	c = round1(c, d, a, b, m[6] , 11);
	b = round1(b, c, d, a, m[7] , 19);
	a = round1(a, b, c, d, m[8] , 3);
	d = round1(d, a, b, c, m[9] , 7);
	c = round1(c, d, a, b, m[10], 11);
	b = round1(b, c, d, a, m[11], 19);
	a = round1(a, b, c, d, m[12], 3);
	d = round1(d, a, b, c, m[13], 7);
	c = round1(c, d, a, b, m[14], 11);
	b = round1(b, c, d, a, m[15], 19);


	// ROUND 2!
	a = round2(a, b, c, d, m[0] , 3);
	d = round2(d, a, b, c, m[4] , 5);
	c = round2(c, d, a, b, m[8] , 9);
	b = round2(b, c, d, a, m[12], 13);
	a = round2(a, b, c, d, m[1] , 3);
	d = round2(d, a, b, c, m[5] , 5);
	c = round2(c, d, a, b, m[9] , 9);
	b = round2(b, c, d, a, m[13], 13);
	a = round2(a, b, c, d, m[2] , 3);
	d = round2(d, a, b, c, m[6] , 5);
	c = round2(c, d, a, b, m[10], 9);
	b = round2(b, c, d, a, m[14], 13);
	a = round2(a, b, c, d, m[3] , 3);
	d = round2(d, a, b, c, m[7] , 5);
	c = round2(c, d, a, b, m[11], 9);
	b = round2(b, c, d, a, m[15], 13);

	// ROUND 3!
	a = round3(a, b, c, d, m[0] , 3);
	d = round3(d, a, b, c, m[8] , 9);
	c = round3(c, d, a, b, m[4] , 11);
	b = round3(b, c, d, a, m[12], 15);
	a = round3(a, b, c, d, m[2] , 3);
	d = round3(d, a, b, c, m[10], 9);
	c = round3(c, d, a, b, m[6] , 11);
	b = round3(b, c, d, a, m[14], 15);
	a = round3(a, b, c, d, m[1] , 3);
	d = round3(d, a, b, c, m[9] , 9);
	c = round3(c, d, a, b, m[5] , 11);
	b = round3(b, c, d, a, m[13], 15);
	a = round3(a, b, c, d, m[3] , 3);
	d = round3(d, a, b, c, m[11], 9);
	c = round3(c, d, a, b, m[7] , 11);
	b = round3(b, c, d, a, m[15], 15);
	
	a.wrapping_add(aa)
}

// FUNCTIONS FOR Challenge 53

fn find_collision(dummy_hash: u32, h: u32) -> (Vec<u32>, Vec<u32>, u32) {
	let mut h1;
	let mut h2;
	let range = Uniform::new_inclusive(0, 0xFFFF_FFFFu32);
	let mut msg = rand::thread_rng().sample_iter(&range).take(16).collect::<Vec<u32>>();

	// hash maps for the collisions
	let mut dummy_map = HashMap::new();
	let mut single_map = HashMap::new();

	let dummy_msg;
	let single_msg;

	loop {
		h1 = hashfn(&msg, dummy_hash);
		dummy_map.insert(h1, msg.clone());
		h2 = hashfn(&msg, h);
		single_map.insert(h2, msg.clone());
		if dummy_map.contains_key(&h2) { // we found a collision
			dummy_msg = dummy_map.get(&h2).unwrap().clone();
			single_msg = msg;
			h1 = h2;
			break;
		} else if single_map.contains_key(&h1) { // we found a collision
			single_msg = single_map.get(&h1).unwrap().clone();
			dummy_msg = msg;
			break;
		}
		msg = rand::thread_rng().sample_iter(&range).take(16).collect::<Vec<u32>>();
	}
	// NOTE: the hash value isn't in the final form!
	//       for MD4 you are supposed to convert to big endian
	(dummy_msg, single_msg, h1)
}

// FUNCTIONS FOR Challenge 54
#[derive(Debug)]
struct Node {
	hash: u32,
	msg: Option<Vec<u32>>,
	parent: Option<Rc<Mutex<Node>>>,
}

impl Node {
	fn new(hash: u32) -> Node {
		Node {
			hash: hash,
			msg: None,
			parent: None,
		}
	}
}

// return a mapping of hash values to an index in the funnel leaves
fn generate_funnel(k: usize) -> (HashMap<u32, usize>, Vec<Rc<Mutex<Node>>>, u32) {
	let num_leaves = 1 << k; // generate 2**k leaves
	let range = Uniform::new_inclusive(0, 0xFFFF_FFFFu32);

	// (1) Generate initial hash states
	let mut hashm = HashMap::with_capacity(num_leaves);
	let mut initial_states = (0..num_leaves).map(|i| {
		let hash = range.sample(&mut rand::thread_rng());
		(&mut hashm).insert(hash, i);
		Rc::new(Mutex::new(Node::new(hash)))
	}).collect::<Vec<Rc<Mutex<Node>>>>();

	// (2) build the funnel
	let mut funnel = compute_next_level(&mut initial_states);
	while funnel.len() != 1 {
		funnel = compute_next_level(&mut funnel[..]);	
		println!("\tfunnel len: {}", funnel.len());
	}
	let root = funnel[0].lock().unwrap();

	(hashm, initial_states, root.hash)
}

fn compute_next_level(hashes: &mut [Rc<Mutex<Node>>]) -> Vec<Rc<Mutex<Node>>> {
	assert!(hashes.len() % 2 == 0);

	let mut ret_hashes = Vec::with_capacity(hashes.len() >> 1);

	for pair in hashes.chunks_mut(2) {
		let mut n1 = pair[0].lock().unwrap();
		let mut n2 = pair[1].lock().unwrap();
		let (msg1, msg2, hash) = find_collision(n1.hash, n2.hash);
		let mut parent = Rc::new(Mutex::new(Node::new(hash)));

		n1.parent = Some(parent.clone());
		n1.msg = Some(msg1);
		n2.parent = Some(parent.clone());
		n2.msg = Some(msg2);

		ret_hashes.push(parent);
	}

	ret_hashes
}

fn main() {
	let k = 10;
	let block_size = 16;
	// (1) Generate the funnel of hashes
	println!("Generating funnel with {} leaves...", 1 << k);
	let (hashm, leaves, root_hash) = generate_funnel(k);
	println!("Done!");

	// (2) make a fake prediction
	let mut fake_prediction = bytes_to_u32s(b"The Clevland Cavaliers will win the NBA finals in seven games. It will be a battle for the ages, by which I mean that there shan't be another battle like it for a long time. It will be a grand battle. Lebron James will play an integral role. He will score points, he will have assists, and he will also have rebounds. J.R. Smith will do something silly, at least once.However, do not fear, for they will vanquish their enemies in the end! The referees will make it so. That's why they get paid the big bucks son!".to_vec());

	// (3) determine our expected final hash
	let msg_len = k + fake_prediction.len() / block_size + 1; // one is for the glue block
	let mut padding = bytes_to_u32s(gen_padding_block(msg_len as usize));
	let final_hash = hashfn(&padding, root_hash);
	println!("Expected hash: {}", final_hash);

	// (4) hash the fake message
	let prediction_hash = md4lite(&fake_prediction);

	// (5) find a glue block
	let range = Uniform::new_inclusive(0, 0xFFFF_FFFFu32);
	let mut glue = rand::thread_rng().sample_iter(&range).take(block_size).collect::<Vec<u32>>();
	let index;
	println!("Searching for a glue block...");
	loop {
		let hash_glue = hashfn(&glue, prediction_hash);
		if let Some(i) = hashm.get(&hash_glue) {
			index = *i;
			break;
		}
		glue = rand::thread_rng().sample_iter(&range).take(block_size).collect::<Vec<u32>>();
	}
	println!("Done!");

	let mut node = leaves[index].clone();
	// (6) traverse the tree to determine the messages to use
	println!("Creating the final message...");
	fake_prediction.append(&mut glue);
	loop {
		let parent;
		{
			let n = node.lock().unwrap();
			if let Some(ref msg) = n.msg {
				fake_prediction.extend_from_slice(&msg);
			}
			match n.parent {
				None => break,
				Some(ref p) => parent = p.clone(),
			}
		}
		node = parent;
	}
	fake_prediction.append(&mut padding);
	println!("Done!");

	// (7) verify the hash
	println!("Calculating hash for verification...");
	let fake_hash = md4lite(&fake_prediction);
	println!("Done!");
	println!("fake_hash == final_hash? {}", fake_hash == final_hash);
	println!("fake_hash: {}", fake_hash);
	println!("final_hash: {}", final_hash);
}
