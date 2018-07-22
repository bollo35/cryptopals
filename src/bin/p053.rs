extern crate rand;

use std::collections::HashMap;

use rand::Rng;
use rand::distributions::{Uniform};
use std::mem;

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

fn pad(mut msg: Vec<u8>, additional_len: usize) -> Vec<u8> {
	let l = msg.len() * 8;
	msg.push(0x80); // append the 1 (along with 7 zeroes)
	
	// we subtract 8 to account for the 0x80 byte appended
	let k = 448usize.wrapping_sub(l % 512).wrapping_sub(8) % 512;
	let bytes = k / 8 + if k%8 > 0 { 1 } else { 0 };
	msg.append(&mut vec![0; bytes]);
	let total_len = additional_len * 8 + l;
	let len64b = unsafe { mem::transmute::<u64, [u8; 8]>( (total_len as u64).to_le()) };
	msg.extend_from_slice(&len64b[..]);

	msg
}

fn bytes_to_u32s(msg: Vec<u8>) -> Vec<u32> {
	assert!(msg.len() % 16 == 0);
	msg.chunks(4).fold(Vec::with_capacity(msg.len()/4 + 1), | mut acc, curr | { 
		let data = unsafe {mem::transmute::<[u8; 4],u32>([curr[0], curr[1], curr[2], curr[3]])};
		acc.push(data.to_le());
		acc
	})
}

fn u32s_to_bytes(msg: &[u32]) -> Vec<u8> {
	msg.iter().fold(Vec::with_capacity(msg.len() * 4), |mut acc, word| {
		let arr = unsafe { mem::transmute::<u32, [u8; 4]>(word.to_le()) };
		acc.extend_from_slice(&arr[..]);
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
	
	a = a.wrapping_add(aa);
	b = b.wrapping_add(bb);
	c = c.wrapping_add(cc);
	d = d.wrapping_add(dd);
	a
}

// FUNCTIONS FOR Challenge 53
#[derive(Hash, Clone, PartialEq, Eq)]
struct Collision {
	dummy_msg: Vec<u32>,
	single_msg: Vec<u32>,
	hash: u32,
	num_blocks: usize,
}

fn gen_collision_list(kin: usize, dummy_block: &[u32]) -> Vec<Collision> {
	println!("Allocating to generate collision list");
	let mut collisions = Vec::with_capacity(kin);

	let mut h: u32 = 0x67452301;

	// iterate from k-1 to 0
	for k in (0..kin).rev() {
		let num_blocks = 1 << k;
		let (dummy_msg, single_msg, hash) = many_to_single_collision(dummy_block, h, num_blocks);
		let collision = Collision {
			dummy_msg: dummy_msg,
			single_msg: single_msg,
			hash: hash,
			num_blocks: num_blocks + 1,
		};
		h = hash;
		collisions.push(collision);
	}

	collisions
}

fn many_to_single_collision(dummy_block: &[u32], h: u32, num_blocks: usize) -> (Vec<u32>, Vec<u32>, u32) {
	let mut dummy_hash = h;

	for _ in 0..num_blocks {
		dummy_hash = hashfn(dummy_block, dummy_hash);
	}

	find_collision(dummy_hash, h)
}

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
	(dummy_msg, single_msg, h1)
}

fn as_block_len(len: usize, block_size: usize) -> usize {
	len / block_size
}

fn main() {
	let k = 10;
	let block_size = 16; // block size in 32 bit words
	let num_blocks = 1 << k; 
	let range = Uniform::new_inclusive(0, 255u8);

	let m = rand::thread_rng().sample_iter(&range).take(num_blocks * block_size * 4).collect::<Vec<u8>>();

	let m = bytes_to_u32s(pad(m, 0));
	let mut hash_to_indices = HashMap::new();

	// step 1: Generate an expandle message!
	let range = Uniform::new_inclusive(0, 0xFFFF_FFFFu32);
	let dummy_block = rand::thread_rng().sample_iter(&range).take(block_size).collect::<Vec<u32>>();
	let expandable = gen_collision_list(k, &dummy_block);

/*
	// TRUST BUT VERIFY!
	let th: u32 = 0x67452301;
	let mut dummy_blocks  = Vec::with_capacity(num_blocks * block_size);
	let mut single_blocks = Vec::with_capacity(k * block_size);
	let mut dummy_hash = th.clone();
	for cinfo in expandable.iter() {
		for _ in 0..(cinfo.num_blocks-1) {
			dummy_blocks.extend_from_slice(&dummy_block);
		}

		for _ in 0..(cinfo.num_blocks-1) {
			dummy_hash = hashfn(&dummy_block, &dummy_hash);
		}

		let dum_h = md4lite(&dummy_blocks);
		println!("dummy hash == dum_h? {}", dummy_hash == dum_h);
		dummy_blocks.extend_from_slice(&cinfo.dummy_msg);
		let dum_h = md4lite(&dummy_blocks);

		single_blocks.extend_from_slice(&cinfo.single_msg);
		let single_h = md4lite(&single_blocks);
		dummy_hash   = single_h;

		println!("----------");
		println!("Dummy hash: {}", dum_h.to_hex_string());
		println!("Singl hash: {}", single_h.to_hex_string());
		println!("Expec hash: {}", cinfo.hash.to_hex_string());
	}
*/

	// step 2: Hash M, keep track of the intermediate hash states to block index
	// hash and keep up with the hash value and the message index
	let mut h: u32 = 0x67452301;

	for (i, chunk) in m.chunks(16).enumerate() {
		h = hashfn(chunk, h);
		hash_to_indices.insert(h, i);
	}

	// try to find a linking block to our long message
	// it seems like you just pick random blocks to hash with your expandable message
	// concatenate them and then append the rest of the message
	let cinfo = expandable.last().unwrap().clone();
	let mut bridge = rand::thread_rng().sample_iter(&range).take(block_size).collect::<Vec<u32>>();

	let lo_bound = k;
	let hi_bound = (1 << k) + k - 1;
	let collision_index;
	loop {
		let hash = hashfn(&bridge, cinfo.hash);
		if let Some(&index) = hash_to_indices.get(&hash) {
			if lo_bound <= index  && index <= hi_bound {
				collision_index = index;
				println!("COLLISION at {}: {:08x} \n\tSTART: {:08x}", index, hash, cinfo.hash);
				break;
			}
		}
		bridge = rand::thread_rng().sample_iter(&range).take(block_size).collect::<Vec<u32>>();
	}

	// mask will represent which choice we take (0 = 1 block, 1 = 2^k + 1 blocks)
	// the bits in mask are reversed with respect to the expandable message array
	// so bit 0 corresponds to our choice for the last block in the expandable message array
	//   (i.e. 0 = choose 1 message, 1 = choose 2 messages)

	let mask = collision_index - k;
	let mut collider = Vec::with_capacity(m.len());
	for (i, c) in expandable.iter().enumerate() {
		// don't forget to add the bridge!
		if as_block_len(collider.len(), block_size) == collision_index {
			break;
		} else if mask & (1 << (k-i-1)) != 0 {
			for _ in 0..(c.num_blocks-1) {
				collider.extend_from_slice(&dummy_block);
			}
			collider.extend_from_slice(&c.dummy_msg);
		} else {
			collider.extend_from_slice(&c.single_msg);
		}
	}
	
	// add the bridge
	collider.extend_from_slice(&bridge);

	// add the rest of the message
	collider.extend_from_slice(&m[block_size*(collision_index+1)..]);

	// confirm that all is well
	let original = md4lite(&m);
	let forgery = md4lite(&collider);

	println!("og == forgery? {}", original == forgery);
	println!("og hash: {:08x}", original);
	println!("forged hash: {:08x}", forgery);
}

