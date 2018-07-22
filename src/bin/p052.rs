extern crate ooga;
use ooga::byte_utils::ToHexString;

extern crate openssl;
extern crate rand;

use openssl::symm::{Cipher, encrypt};
//use std::ops::{Add, Div, Mul, Sub};
use std::collections::HashSet;
use std::collections::HashMap;
use rand::Rng;

fn pad(data: &[u8], block_len: usize) -> Vec<u8> {
	if data.len() % block_len == 0 {
		data.to_vec()
	} else {
		let zeroes = vec![0u8; block_len - (data.len() % block_len)];
		let mut ret = data.to_vec();
		ret.extend_from_slice(&zeroes);
		ret
	}
}

// let H be 16 bits
fn md(msg: &[u8], h: &[u8]) -> [u8; 2] {
	const OUTPUT_BYTE_LEN : usize = 2;
	const BIT_LEN : usize = 128;
	const BLOCK_LEN : usize = BIT_LEN / 8;
	assert!(h.len() == OUTPUT_BYTE_LEN);
	let mut h = h.to_vec();
	h = pad(&h, BLOCK_LEN);
	let m = pad(msg, OUTPUT_BYTE_LEN); 
	let iv = vec![0u8; BLOCK_LEN];

	for mi in m.chunks(OUTPUT_BYTE_LEN) {
		let msg = pad(&mi, BLOCK_LEN);
		let ciphertext = encrypt(
		                   Cipher::aes_128_cbc(),
		                   &h,
		                   Some(&iv),
		                   &msg).unwrap();
		h = pad(&ciphertext[0..OUTPUT_BYTE_LEN], BLOCK_LEN);
	}
	[h[0], h[1]]
}

// let G be 24 bits
fn g(msg: &[u8], h: &[u8]) -> [u8; 4] {
	const OUTPUT_BYTE_LEN : usize = 4;
	const BIT_LEN : usize = 128;
	const BLOCK_LEN : usize = BIT_LEN / 8;
	assert!(h.len() == OUTPUT_BYTE_LEN);
	let mut h = h.to_vec();
	h = pad(&h, BLOCK_LEN);
	let m = pad(msg, OUTPUT_BYTE_LEN); 
	let iv = vec![0u8; BLOCK_LEN];

	for mi in m.chunks(OUTPUT_BYTE_LEN) {
		let msg = pad(&mi, BLOCK_LEN);
		let ciphertext = encrypt(
		                   Cipher::aes_128_cbc(),
		                   &h,
		                   Some(&iv),
		                   &msg).unwrap();
		h = pad(&ciphertext[0..OUTPUT_BYTE_LEN], BLOCK_LEN);
	}

	[h[0], h[1], h[2], h[3]]
}

fn super_hash(msg: &[u8], h: &[u8]) -> [u8; 6] {
	// generate hash with md
	let h1 = md(msg, &h[0..2]);

	// generate hash with g
	let h2 = g(msg, &h[2..]);

	// cat them together
	[ h1[0], h1[1], h2[0], h2[1], h2[2], h2[3]]
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct Collision {
	m: [Vec<u8>; 2],
}

// return a collision and hash state
fn find_collision(init_hash: [u8; 2]) -> (Collision, [u8; 2]) {
	// hash map to hold previous messages
	let mut msg_map : HashMap<[u8; 2], Vec<u8>> = HashMap::new();

	let collision;
	let hash_state : [u8; 2];

	'collision: loop {
		let msg = rand::thread_rng().gen_iter::<u8>().filter(|&x| x != 0).take(4).collect::<Vec<u8>>();
		let output = md(&msg, &init_hash);
		if msg_map.contains_key(&output) {
			let m = msg_map.get(&output).unwrap();
			if *m != msg {
				hash_state = output.clone();
				collision = Collision {
					m: [m.clone(), msg.to_vec()],
				};
				break 'collision;
			}
		} else {
			msg_map.insert(output, msg.to_vec());
		}
	}

	(collision, hash_state)
}

fn gen_collisions(num_collisions: usize, init_hash: &[u8; 2], record: &mut HashSet<[u8; 2]>) -> Vec<Collision> {
	let mut collisions = Vec::with_capacity(num_collisions);

	let mut h = init_hash.clone();

	for num_found in 0..num_collisions {
		let (mut collision, mut hash) = find_collision(h);
		// make sure it's not a collision that we found previously
		while num_found == 0 && record.contains(&hash) {
			let (c, h_again) = find_collision(h);
			hash = h_again;
			collision = c;
		}

		// store the first collision so we don't start from here again
		if num_found == 0 {
			record.insert(hash);
		}
		collisions.push(collision);
		h = hash;
	}
	collisions
}

#[derive(Debug, Clone)]
struct CollisionInfo {
	choice: usize,
	index: usize,
	collision_group: usize,
}

impl CollisionInfo {
	fn new(choice: usize, index: usize, collision_group: usize) -> CollisionInfo {
		CollisionInfo {
			choice: choice,
			index: index,
			collision_group: collision_group,
		}
	}
}

// NOTE: the messages that are generated for finding collisions in md
//       are 4 bytes long because otherwise we'll get conflicting hashes
//       since we're trying to incrementally generate the hashes in the
//       collision loop in main.
//       Say the messages were of length 2. g's block size is 4, so when
//       hashing, it will extend the message to length 4. However, when
//       we create the final message it might be much longer than 2, so
//       instead of getting padded with 0's g, would grab additional bytes
//       and hash them as well. Took me forever to realize this. ARGGGH!!!
fn main() {
	let g_init = [ 1u8, 2u8, 3u8, 4u8];
	let f_init = [0xcau8, 0xfeu8];
	let super_init = [f_init[0], f_init[1], g_init[0], g_init[1], g_init[2], g_init[3]];

	// (1) Generate 2 ^ (32/2) collision in md(...)
	let num_collisions : usize = 16;
	println!("Generating {} collisions", num_collisions);
	let mut record = HashSet::new();
	let mut collisions = gen_collisions(num_collisions, &f_init, &mut record);
	println!("Done!");

	let mut gen_called = 1;

	let mut hashes : HashMap<[u8; 6], CollisionInfo> = HashMap::new();
	let mut collision_stack : Vec<Vec<Collision>> = Vec::new();

	// (2) try to find a collision based on pool of collisions in f
	// (3) if we don't succeed, then dust ourselves off and try again...try again... (optional for now :P)
	// i could be more "clever" here and save parts of the hashes since each bit pattern maps to a hash state
	// make - I don't feel like doing that though... 
	let combo0;
	let combo1;
	let colliding_hash;
	'search: loop {
		collision_stack.push(collisions.clone());
		for i in 0..(1 << num_collisions) {
			// for each message, we have a choice of the first message or the second one
			// choice will be a binary number that represents the choice at each position
			let choice = i;
			let mut hash_state = super_init.clone();
			for (index, collision) in collisions.iter().enumerate() {
				let m = (choice >> index) & 1;
				let msg = &collision.m[m];
				hash_state = super_hash(msg, &hash_state);
				// check for collision
				if hashes.contains_key(&hash_state) {
					let combo = hashes.get(&hash_state).unwrap().clone();
					
					let new_combo = CollisionInfo::new(choice, index, gen_called - 1);
	
					// just to make sure that we're not looking at the same message
					// since multiple numbers will have the same bit pattern for lower
					// bits. It would be better to mask the choices based on the index 
					// and check for equality, but this should be sufficient
					if combo.collision_group != new_combo.collision_group || combo.index != new_combo.index {
						// we've found a collision!
						println!("combo0: {:?}", combo);
						println!("combo1: {:?}", new_combo);
						combo0 = combo;
						combo1 = new_combo;
						colliding_hash = hash_state.clone();
						break 'search;
					}
				}
				// insert hash into hashmap
				let collision_info  = CollisionInfo::new(choice, index, gen_called - 1);
				hashes.insert(hash_state, collision_info);
			}
		}
		println!("need to generate more collisions!");
		gen_called += 1;
		collisions = gen_collisions(num_collisions, &f_init, &mut record);
	}

	println!("Called gen_collisions {} times", gen_called);

	// (4) print our colliding messages

	let mut msg0 = Vec::with_capacity(4*combo0.index);
	let mut msg1 = Vec::with_capacity(4*combo1.index);

	// reconstruct messages
	for i in 0..(combo0.index+1) {
		let m = (combo0.choice >> i) & 1;
		msg0.extend_from_slice(&collision_stack[combo0.collision_group][i].m[m]);
	}

	for i in 0..(combo1.index+1) {
		let m = (combo1.choice >> i) & 1;
		msg1.extend_from_slice(&collision_stack[combo1.collision_group][i].m[m]);
	}

	println!("--------M E S S A G E S-----------");
	println!("msg0: {:?}", msg0);
	println!("---------------");
	println!("msg1: {:?}", msg1);

	let m0_hash = super_hash(&msg0, &super_init);
	let m1_hash = super_hash(&msg1, &super_init);
	println!("----------H A S H E S-------------");
	println!("expected hash: {:?}", colliding_hash.to_hex_string());
	println!("msg0: {}", m0_hash.to_hex_string());
	println!("msg1: {}", m1_hash.to_hex_string());
	println!("hash(msg0) == hash(msg1)? {}", m0_hash == m1_hash);
}

