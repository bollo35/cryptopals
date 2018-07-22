extern crate rand;
use rand::Rng;
use rand::distributions::{Uniform};
use std::mem;
use std::collections::HashSet;

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

pub fn md4(msg: Vec<u8>) -> ([u32; 4], IntermediateValues) {
	let h: [u32; 4] = [
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476,
	];
	md4_attack(msg, h, 0)
}

pub fn md4_attack(msg: Vec<u8>, h: [u32; 4], additional_len: usize) -> ([u32; 4], IntermediateValues) {
	let msg = bytes_to_u32s(pad(msg, additional_len));
	let mut a = h[0];
	let mut b = h[1];
	let mut c = h[2];
	let mut d = h[3];

	let mut vals = IntermediateValues::new();
	// process in 16 word chunks (512 bit)
	for chunk in msg.chunks(16) {
		let x = chunk.clone();
		let aa = a;
		let bb = b;
		let cc = c;
		let dd = d;
	
		vals.a.push(a);
		vals.b.push(b);
		vals.c.push(c);
		vals.d.push(d);

		// ROUND 1!
		a = round1(a, b, c, d, x[0] , 3);
		vals.a.push(a);
		d = round1(d, a, b, c, x[1] , 7);
		vals.d.push(d);
		c = round1(c, d, a, b, x[2] , 11);
		vals.c.push(c);
		b = round1(b, c, d, a, x[3] , 19);
		vals.b.push(b);
		a = round1(a, b, c, d, x[4] , 3);
		vals.a.push(a);
		d = round1(d, a, b, c, x[5] , 7);
		vals.d.push(d);
		c = round1(c, d, a, b, x[6] , 11);
		vals.c.push(c);
		b = round1(b, c, d, a, x[7] , 19);
		vals.b.push(b);
		a = round1(a, b, c, d, x[8] , 3);
		vals.a.push(a);
		d = round1(d, a, b, c, x[9] , 7);
		vals.d.push(d);
		c = round1(c, d, a, b, x[10], 11);
		vals.c.push(c);
		b = round1(b, c, d, a, x[11], 19);
		vals.b.push(b);
		a = round1(a, b, c, d, x[12], 3);
		vals.a.push(a);
		d = round1(d, a, b, c, x[13], 7);
		vals.d.push(d);
		c = round1(c, d, a, b, x[14], 11);
		vals.c.push(c);
		b = round1(b, c, d, a, x[15], 19);
		vals.b.push(b);


		// ROUND 2!
		a = round2(a, b, c, d, x[0] , 3);
		vals.a.push(a);
		d = round2(d, a, b, c, x[4] , 5);
		vals.d.push(d);
		c = round2(c, d, a, b, x[8] , 9);
		vals.c.push(c);
		b = round2(b, c, d, a, x[12], 13);
		vals.b.push(b);
		a = round2(a, b, c, d, x[1] , 3);
		vals.a.push(a);
		d = round2(d, a, b, c, x[5] , 5);
		vals.d.push(d);
		c = round2(c, d, a, b, x[9] , 9);
		vals.c.push(c);
		b = round2(b, c, d, a, x[13], 13);
		vals.b.push(b);
		a = round2(a, b, c, d, x[2] , 3);
		vals.a.push(a);
		d = round2(d, a, b, c, x[6] , 5);
		vals.d.push(d);
		c = round2(c, d, a, b, x[10], 9);
		vals.c.push(c);
		b = round2(b, c, d, a, x[14], 13);
		vals.b.push(b);
		a = round2(a, b, c, d, x[3] , 3);
		vals.a.push(a);
		d = round2(d, a, b, c, x[7] , 5);
		vals.d.push(d);
		c = round2(c, d, a, b, x[11], 9);
		vals.c.push(c);
		b = round2(b, c, d, a, x[15], 13);
		vals.b.push(b);

		// ROUND 3!
		a = round3(a, b, c, d, x[0] , 3);
		vals.a.push(a);
		d = round3(d, a, b, c, x[8] , 9);
		vals.d.push(d);
		c = round3(c, d, a, b, x[4] , 11);
		vals.c.push(c);
		b = round3(b, c, d, a, x[12], 15);
		vals.b.push(b);
		a = round3(a, b, c, d, x[2] , 3);
		vals.a.push(a);
		d = round3(d, a, b, c, x[10], 9);
		vals.d.push(d);
		c = round3(c, d, a, b, x[6] , 11);
		vals.c.push(c);
		b = round3(b, c, d, a, x[14], 15);
		vals.b.push(b);
		a = round3(a, b, c, d, x[1] , 3);
		vals.a.push(a);
		d = round3(d, a, b, c, x[9] , 9);
		vals.d.push(d);
		c = round3(c, d, a, b, x[5] , 11);
		vals.c.push(c);
		b = round3(b, c, d, a, x[13], 15);
		vals.b.push(b);
		a = round3(a, b, c, d, x[3] , 3);
		vals.a.push(a);
		d = round3(d, a, b, c, x[11], 9);
		vals.d.push(d);
		c = round3(c, d, a, b, x[7] , 11);
		vals.c.push(c);
		b = round3(b, c, d, a, x[15], 15);
		vals.b.push(b);
		
		a = a.wrapping_add(aa);
		b = b.wrapping_add(bb);
		c = c.wrapping_add(cc);
		d = d.wrapping_add(dd);
	}
	([a.to_be(), b.to_be(), c.to_be(), d.to_be()], vals)
}

fn fmt_hash(h: &[u32; 4]) -> String {
	format!("{:08x}{:08x}{:08x}{:08x}",h[0], h[1], h[2], h[3])
}

// NOTE: 1-indexed
fn clear_bit(value: u32, bit: usize) -> u32 {
	assert!(bit >= 1 && bit <= 32);
	let mask = (1 << (bit-1)) as u32;
	value & !mask
}

fn clear_bits(value: u32, bits: Vec<usize>) -> u32 {
	bits.iter().fold(value, |acc, &bit| {
		if bit < 1 || bit > 32 {
			panic!("invalid bit offset");
		} else {
			let mask = (1 << (bit-1)) as u32;
			acc & !mask
		}
	})
}

fn get_bits(value: u32, bits: Vec<usize>) -> u32 {
	let mask = bits.iter().fold(0, |acc, &bit| {
		if bit < 1 || bit > 32 {
			panic!("invalid bit offset");
		} else {
			let bmask = (1 << (bit-1)) as u32;
			acc | bmask
		}
	});
	value & mask
}

// NOTE: 1-indexed
fn set_bit(value: u32, bit: usize) -> u32 {
	assert!(bit >= 1 && bit <= 32);
	let mask = (1 << (bit-1)) as u32;
	value | mask
}

fn set_bits(value: u32, bits: Vec<usize>) -> u32 {
	bits.iter().fold(value, |acc, &bit| {
		if bit < 1 || bit > 32 {
			panic!("invalid bit offset");
		} else {
			let bmask = (1 << (bit-1)) as u32;
			acc | bmask
		}
	})
}

fn get_bit(value: u32, bit: usize) -> u32 {
	assert!(bit >= 1 && bit <= 32);
	let mask = (1 << (bit-1)) as u32;
	value & mask
}

pub struct IntermediateValues {
	a: Vec<u32>,
	b: Vec<u32>,
	c: Vec<u32>,
	d: Vec<u32>,
}

impl IntermediateValues {
	fn new() -> IntermediateValues {
		IntermediateValues {
			a: Vec::with_capacity(16),
			b: Vec::with_capacity(16),
			c: Vec::with_capacity(16),
			d: Vec::with_capacity(16),
		}
	}
}

// I implemented all of these by hand because...sunk-cost fallacy???
fn modify_first_round(m: &[u32], h: &[u32; 4]) -> (Vec<u32>, IntermediateValues)  {
	let mut new_msg = Vec::with_capacity(16);
	let mut vals = IntermediateValues::new();

	let mut a = h[0];
	let mut b = h[1];
	let mut c = h[2];
	let mut d = h[3];

	vals.a.push(a);
	vals.b.push(b);
	vals.c.push(c);
	vals.d.push(d);

	let mut la = a;
	let mut lb = b;
	let mut lc = c;
	let mut ld = d;

	let mut msg : u32;

	// [1]
	a = round1(a, b, c, d, m[0] , 3);
	a = clear_bit(a, 7) ^ get_bit(b, 7);
	msg = a.rotate_right(3).wrapping_sub(la).wrapping_sub( f(b, c, d) );
	new_msg.push(msg);
	vals.a.push(a);
	la = a;

	d = round1(d, a, b, c, m[1] , 7);
	d ^= get_bit(d, 7) ^ get_bit(d, 8)  ^ get_bit(a, 8) ^ get_bit(d, 11) ^ get_bit(a, 11);
	msg = d.rotate_right(7).wrapping_sub(ld).wrapping_sub( f(a, b, c) );
	new_msg.push(msg);
	vals.d.push(d);
	ld = d;
	
	c = round1(c, d, a, b, m[2] , 11);
	c = clear_bit(set_bit(set_bit(c, 7), 8), 11) ^ get_bit(c, 26) ^ get_bit(d, 26);
	msg = c.rotate_right(11).wrapping_sub(lc).wrapping_sub( f(d, a, b) );
	new_msg.push(msg);
	vals.c.push(c);
	lc = c;

	b = round1(b, c, d, a, m[3] , 19);
	b = clear_bit( clear_bit( clear_bit( set_bit(b, 7), 8), 11), 26);
	msg = b.rotate_right(19).wrapping_sub(lb).wrapping_sub( f(c, d, a) );
	new_msg.push(msg);
	vals.b.push(b);
	lb = b;

	// [2]
	a = round1(a, b, c, d, m[4] , 3);
	a = clear_bit( set_bit( set_bit(a, 8), 11), 26) ^ get_bit(a, 14) ^ get_bit(b, 14);
	msg = a.rotate_right(3).wrapping_sub(la).wrapping_sub( f(b, c, d) );
	new_msg.push(msg);
	vals.a.push(a);
	la = a;

	d = round1(d, a, b, c, m[5] , 7);
	d = set_bit(clear_bits(d, vec![14, 19, 20, 21, 22]), 26) ^ get_bits(a, vec![19, 20, 21, 22]);
	msg = d.rotate_right(7).wrapping_sub(ld).wrapping_sub( f(a, b, c ) );
	new_msg.push(msg);
	vals.d.push(d);
	ld = d;

	c = round1(c, d, a, b, m[6] , 11);
	c = set_bit(clear_bits(c, vec![13, 14, 15, 19, 20, 22]), 21) ^ get_bits(d, vec![13, 15]);
	msg = c.rotate_right(11).wrapping_sub(lc).wrapping_sub( f(d, a, b) );
	new_msg.push(msg);
	vals.c.push(c);
	lc = c;

	b = round1(b, c, d, a, m[7] , 19);
	b = clear_bits(set_bits(b, vec![13, 14]), vec![15, 17, 19, 20, 21, 22]) ^ get_bit(c, 17);
	msg = b.rotate_right(19).wrapping_sub(lb).wrapping_sub( f(c, d, a) );
	new_msg.push(msg);
	vals.b.push(b);
	lb = b;

	// [3]
	a = round1(a, b, c, d, m[8] , 3);
	a = set_bits( clear_bits(a, vec![17, 19, 20, 21, 23, 26]), vec![13, 14, 15, 22]) ^ get_bits(b, vec![23, 26]);
	msg = a.rotate_right(3).wrapping_sub(la).wrapping_sub( f(b, c, d) );
	new_msg.push(msg);
	vals.a.push(a);
	la = a;
	
	d = round1(d, a, b, c, m[9] , 7);
	d = set_bits( clear_bits(d, vec![17, 20, 23, 30]), vec![13, 14, 15, 21, 22, 26]) ^ get_bit(a, 30);
	msg = d.rotate_right(7).wrapping_sub(ld).wrapping_sub( f(a, b, c ) );
	new_msg.push(msg);
	vals.d.push(d);
	ld = d;

	c = round1(c, d, a, b, m[10], 11);
	c = set_bits( clear_bits(c, vec![20, 21, 22, 23, 26, 32]), vec![17, 30]) ^ get_bit(d, 32);
	msg = c.rotate_right(11).wrapping_sub(lc).wrapping_sub( f(d, a, b) );
	new_msg.push(msg);
	vals.c.push(c);
	lc = c;

	b = round1(b, c, d, a, m[11], 19);
	b = set_bits( clear_bits(b, vec![20, 23, 30, 32]), vec![21, 22, 26]) ^ get_bit(c, 23);
	msg = b.rotate_right(19).wrapping_sub(lb).wrapping_sub( f(c, d, a) );
	new_msg.push(msg);
	vals.b.push(b);
	lb = b;

	// [4]
	a = round1(a, b, c, d, m[12], 3);
	a = set_bit( clear_bits(a, vec![23, 26, 27, 29, 32]), 30) ^ get_bits(b, vec![27, 29]);
	msg = a.rotate_right(3).wrapping_sub(la).wrapping_sub( f(b, c, d) );
	new_msg.push(msg);
	vals.a.push(a);
	la = a;

	d = round1(d, a, b, c, m[13], 7);
	d = set_bits( clear_bits(d, vec![23, 26, 30]), vec![27, 29, 32] );
	msg = d.rotate_right(7).wrapping_sub(ld).wrapping_sub( f(a, b, c ) );
	new_msg.push(msg);
	vals.d.push(d);
	ld = d;

	c = round1(c, d, a, b, m[14], 11);
	c = set_bits( clear_bits(c, vec![19, 27, 29, 30]), vec![23, 26] ) ^ get_bit(d, 19);
	msg = c.rotate_right(11).wrapping_sub(lc).wrapping_sub( f(d, a, b) );
	new_msg.push(msg);
	vals.c.push(c);
	lc = c;

	b = round1(b, c, d, a, m[15], 19);
	b = set_bits( clear_bits(b, vec![19, 30]), vec![26, 27, 29] );
	msg = b.rotate_right(19).wrapping_sub(lb).wrapping_sub( f(c, d, a) );
	new_msg.push(msg);
	vals.b.push(b);
	lb = b;

	(new_msg, vals)
}

fn modify_second_round(mut m: Vec<u32>, mut vals: IntermediateValues) -> (Vec<u32>, IntermediateValues) {
	
	let mut a = vals.a[4];
	let mut b = vals.b[4];
	let mut c = vals.c[4];
	let mut d = vals.d[4];

	// [5]
	a = round2(a, b, c, d, m[0] , 3);
	let pairs = [ ( (get_bit(vals.c[4], 19) >> 18) as u32, 19usize), 
	              (1, 26usize),
	              (0, 27usize),
	              (1, 29usize),
	              (1, 32usize)];
	// adjust a5
	for (value, bit_pos) in pairs.iter() {
		a = clear_bit(a, *bit_pos) ^ (value << (*bit_pos-1));
		// calculate m[0] based on this new a
		m[0] = a.rotate_right(3).wrapping_sub(vals.a[4]).wrapping_sub( g(vals.b[4], vals.c[4], vals.d[4]) ).wrapping_sub(0x5A827999);
		vals.a[1] = round1(vals.a[0], vals.b[0], vals.c[0], vals.d[0], m[0] , 3);
		m[1] = vals.d[1].rotate_right(7).wrapping_sub(vals.d[0]).wrapping_sub( f(vals.a[1], vals.b[0], vals.c[0]) );
		m[2] = vals.c[1].rotate_right(11).wrapping_sub(vals.c[0]).wrapping_sub( f(vals.d[1], vals.a[1], vals.b[0]) );
		m[3] = vals.b[1].rotate_right(19).wrapping_sub(vals.b[0]).wrapping_sub( f(vals.c[1], vals.d[1], vals.a[1]) );
		m[4] = vals.a[2].rotate_right(3).wrapping_sub(vals.a[1]).wrapping_sub( f(vals.b[1], vals.c[1], vals.d[1]) );
	}
	vals.a.push(a);

	d = round2(d, a, b, c, m[4] , 5);
	// adjust d5
	let pairs = [ ( (get_bit(vals.a[5], 19) >> 18) as u32, 19usize),
	              ( (get_bit(vals.b[4], 26) >> 25) as u32, 26usize),
	              ( (get_bit(vals.b[4], 27) >> 26) as u32, 27usize),
	              ( (get_bit(vals.b[4], 29) >> 28) as u32, 29usize),
	              ( (get_bit(vals.b[4], 32) >> 31) as u32, 32usize) ]; 
	for (value, bit_pos) in pairs.iter() {
		d = clear_bit(d, *bit_pos) ^ (value << (*bit_pos-1));
		// calculate m[4]
		m[4] = d.rotate_right(5).wrapping_sub(vals.d[4]).wrapping_sub( g(vals.a[5], vals.b[4], vals.c[4]) ).wrapping_sub(0x5A827999);
		vals.a[2] = round1(vals.a[1], vals.b[1], vals.c[1], vals.d[1], m[4], 3);
		m[5] = vals.d[2].rotate_right(7).wrapping_sub(vals.d[1]).wrapping_sub( f(vals.a[2], vals.b[1], vals.c[1]) );
		m[6] = vals.c[2].rotate_right(11).wrapping_sub(vals.c[1]).wrapping_sub( f(vals.d[2], vals.a[2], vals.b[1]) );
		m[7] = vals.b[2].rotate_right(19).wrapping_sub(vals.b[1]).wrapping_sub( f(vals.c[2], vals.d[2], vals.a[2]) );
		m[8] = vals.a[3].rotate_right(3).wrapping_sub(vals.a[2]).wrapping_sub( f(vals.b[2], vals.c[2], vals.d[2]) );
	}
	vals.d.push(d);

	c = round2(c, d, a, b, m[8] , 9);
	// adjust c5
	let pairs = [ ( (get_bit(vals.d[5], 26) >> 25) as u32, 26usize),
	              ( (get_bit(vals.d[5], 27) >> 26) as u32, 27usize),
	              ( (get_bit(vals.d[5], 29) >> 28) as u32, 29usize),
	              ( (get_bit(vals.d[5], 30) >> 29) as u32, 30usize),
	              ( (get_bit(vals.b[4], 32) >> 31) as u32, 32usize) ]; 
	for (value, bit_pos) in pairs.iter() {
		c = clear_bit(c, *bit_pos) ^ (value << (*bit_pos-1));
		// calculate m[8]
		m[8] = c.rotate_right(9).wrapping_sub(vals.c[4]).wrapping_sub( g(vals.d[5], vals.a[5], vals.b[4]) ).wrapping_sub(0x5A827999);
		vals.a[3] = round1(vals.a[2], vals.b[2], vals.c[2], vals.d[2], m[8], 3);
		m[9] = vals.d[3].rotate_right(7).wrapping_sub(vals.d[2]).wrapping_sub( f(vals.a[3], vals.b[2], vals.c[2]) );
		m[10] = vals.c[3].rotate_right(11).wrapping_sub(vals.c[2]).wrapping_sub( f(vals.d[3], vals.a[3], vals.b[2]) );
		m[11] = vals.b[3].rotate_right(19).wrapping_sub(vals.b[2]).wrapping_sub( f(vals.c[3], vals.d[3], vals.a[3]) );
		m[12] = vals.a[4].rotate_right(3).wrapping_sub(vals.a[3]).wrapping_sub( f(vals.b[3], vals.c[3], vals.d[3]) );
		
		
	}
	vals.c.push(c);

	b = round2(b, c, d, a, m[12], 13);
/*
	// WE'RE SKIPPING THIS FOR NOW! IT GETS TRIIIICKY!
	// adjust b5
	let pairs = [ ( (get_bit(vals.c[5], 29) >> 28) as u32, 29),
	              (1, 30),
	              (0, 32) ]; 
	for (value, bit_pos) in pairs.iter() {
		b = clear_bit(b, *bit_pos) ^ (value << (*bit_pos-1));
		// calculate m[12]
		m[12] = b.rotate_right(13).wrapping_sub(vals.b[4]).wrapping_sub( g(vals.c[5], vals,d[5], vals.a[5]) ).wrapping_sub(0x5A827999);

		vals.a[4] = round1(vals.a[3], vals.b[3], vals.c[3], vals.d[3], m[12], 3);
		m[13] = vals.d[3].rotate_right(7).wrapping_sub(vals.d[2]).wrapping_sub( f(vals.a[3], vals.b[2], vals.c[2]) );
		m[14] = vals.c[3].rotate_right(11).wrapping_sub(vals.c[2]).wrapping_sub( f(vals.d[3], vals.a[3], vals.b[2]) );
		m[15] = vals.b[3].rotate_right(19).wrapping_sub(vals.b[2]).wrapping_sub( f(vals.c[3], vals.d[3], vals.a[3]) );
		m[0] = vals.a[4].rotate_right(3).wrapping_sub(vals.a[3]).wrapping_sub( f(vals.b[3], vals.c[3], vals.d[3]) );
	}
*/
	vals.b.push(b);
	

	// [6]
	a = round2(a, b, c, d, m[1] , 3);
	vals.a.push(a);
	d = round2(d, a, b, c, m[5] , 5);
	vals.d.push(d);
	c = round2(c, d, a, b, m[9] , 9);
	vals.c.push(c);
	b = round2(b, c, d, a, m[13], 13);
	vals.b.push(b);

	// [7]
	a = round2(a, b, c, d, m[2] , 3);
	vals.a.push(a);
	d = round2(d, a, b, c, m[6] , 5);
	vals.d.push(d);
	c = round2(c, d, a, b, m[10], 9);
	vals.c.push(c);
	b = round2(b, c, d, a, m[14], 13);
	vals.b.push(b);

	// [8]
	a = round2(a, b, c, d, m[3] , 3);
	d = round2(d, a, b, c, m[7] , 5);
	c = round2(c, d, a, b, m[11], 9);
	b = round2(b, c, d, a, m[15], 13);

	(m, vals)
}

// return the number of constraints that hold for the message
fn check_constraints(vals: IntermediateValues) -> u32 {
	let constraints = [
		(get_bit(vals.a[1], 7), get_bit(vals.b[0], 7)),
		(get_bit(vals.d[1], 7), 0),
		(get_bit(vals.d[1], 8), get_bit(vals.a[1], 8)),
		(get_bit(vals.d[1], 11), get_bit(vals.a[1], 11)),
		(get_bit(vals.c[1], 7), 1 << 6),
		(get_bit(vals.c[1], 8), 1 << 7),
		(get_bit(vals.c[1], 11), 0),
		(get_bit(vals.c[1], 26), get_bit(vals.d[1], 26)),
		(get_bit(vals.b[1], 7), 1 << 6),
		(get_bit(vals.b[1], 8), 0),
		(get_bit(vals.b[1], 11), 0),
		(get_bit(vals.b[1], 26), 0),
		(get_bit(vals.a[2], 8), 1 << 8),
		(get_bit(vals.a[2], 11), 1 << 10),
		(get_bit(vals.a[2], 26), 0),
		(get_bit(vals.a[2], 14), get_bit(vals.b[1], 14)),
		(get_bit(vals.d[2], 14), 0),
		(get_bit(vals.d[2], 19), get_bit(vals.a[2], 19)),
		(get_bit(vals.d[2], 20), get_bit(vals.a[2], 20)),
		(get_bit(vals.d[2], 21), get_bit(vals.a[2], 21)),
		(get_bit(vals.d[2], 22), get_bit(vals.a[2], 22)),
		(get_bit(vals.d[2], 26), 1 << 25),
		(get_bit(vals.c[2], 13), get_bit(vals.d[2], 13)),
		(get_bit(vals.c[2], 14), 0),
		(get_bit(vals.c[2], 15), get_bit(vals.d[2], 15)),
		(get_bit(vals.c[2], 19), 0),
		(get_bit(vals.c[2], 20), 0),
		(get_bit(vals.c[2], 21), 1 << 20),
		(get_bit(vals.c[2], 22), 0),
		(get_bit(vals.b[2], 13), 1 << 12),
		(get_bit(vals.b[2], 14), 1 << 13),
		(get_bit(vals.b[2], 15), 0 << 14),
		(get_bit(vals.b[2], 17), get_bit(vals.c[2], 17)),
		(get_bit(vals.b[2], 19), 0),
		(get_bit(vals.b[2], 20), 0),
		(get_bit(vals.b[2], 21), 0),
		(get_bit(vals.b[2], 22), 0),
		(get_bit(vals.a[3], 13), 1 << 12),
		(get_bit(vals.a[3], 14), 1 << 13),
		(get_bit(vals.a[3], 15), 1 << 14),
		(get_bit(vals.a[3], 17), 0),
		(get_bit(vals.a[3], 19), 0),
		(get_bit(vals.a[3], 20), 0),
		(get_bit(vals.a[3], 21), 0),
		(get_bit(vals.a[3], 22), 1 << 21),
		(get_bit(vals.a[3], 23), get_bit(vals.b[2], 23)),
		(get_bit(vals.a[3], 26), get_bit(vals.b[2], 26)),
		(get_bit(vals.d[3], 13), 1 << 12),
		(get_bit(vals.d[3], 14), 1 << 13),
		(get_bit(vals.d[3], 15), 1 << 14),
		(get_bit(vals.d[3], 17), 0),
		(get_bit(vals.d[3], 20), 0),
		(get_bit(vals.d[3], 21), 1 << 20),
		(get_bit(vals.d[3], 22), 1 << 21),
		(get_bit(vals.d[3], 23), 0),
		(get_bit(vals.d[3], 26), 1 << 25),
		(get_bit(vals.d[3], 30), get_bit(vals.a[3], 30)),
		(get_bit(vals.c[3], 17), 1 << 16),
		(get_bit(vals.c[3], 20), 0),
		(get_bit(vals.c[3], 21), 0),
		(get_bit(vals.c[3], 22), 0),
		(get_bit(vals.c[3], 23), 0),
		(get_bit(vals.c[3], 26), 0),
		(get_bit(vals.c[3], 30), 1 << 29),
		(get_bit(vals.c[3], 32), get_bit(vals.d[3], 32)),
		(get_bit(vals.b[3], 20), 0),
		(get_bit(vals.b[3], 21), 1 << 20),
		(get_bit(vals.b[3], 22), 1 << 21),
		(get_bit(vals.b[3], 23), get_bit(vals.c[3], 23)),
		(get_bit(vals.b[3], 26), 1 << 25),
		(get_bit(vals.b[3], 30), 0),
		(get_bit(vals.b[3], 32), 0),
		(get_bit(vals.a[4], 23), 0),
		(get_bit(vals.a[4], 26), 0),
		(get_bit(vals.a[4], 27), get_bit(vals.b[3], 27)),
		(get_bit(vals.a[4], 29), get_bit(vals.b[3], 29)),
		(get_bit(vals.a[4], 30), 1 << 29),
		(get_bit(vals.a[4], 32), 0),
		(get_bit(vals.d[4], 23), 0),
		(get_bit(vals.d[4], 26), 0),
		(get_bit(vals.d[4], 27), 1 << 26),
		(get_bit(vals.d[4], 29), 1 << 28),
		(get_bit(vals.d[4], 30), 0),
		(get_bit(vals.d[4], 32), 1 << 31),
		(get_bit(vals.c[4], 19), get_bit(vals.d[4], 19)),
		(get_bit(vals.c[4], 23), 1 << 22),
		(get_bit(vals.c[4], 26), 1 << 25),
		(get_bit(vals.c[4], 27), 0),
		(get_bit(vals.c[4], 29), 0),
		(get_bit(vals.c[4], 30), 0),
		(get_bit(vals.b[4], 19), 0),
		(get_bit(vals.b[4], 26), 1 << 25),
		(get_bit(vals.b[4], 27), 1 << 26),
		(get_bit(vals.b[4], 29), 1 << 28),
		(get_bit(vals.b[4], 30), 0),
		(get_bit(vals.a[5], 19), get_bit(vals.c[4], 19)),
		(get_bit(vals.a[5], 26), 1 << 25),
		(get_bit(vals.a[5], 27), 0),
		(get_bit(vals.a[5], 29), 1 << 28),
		(get_bit(vals.a[5], 32), 1 << 31),
		(get_bit(vals.d[5], 19), get_bit(vals.a[5], 19)),
		(get_bit(vals.d[5], 26), get_bit(vals.b[4], 26)),
		(get_bit(vals.d[5], 27), get_bit(vals.b[4], 27)),
		(get_bit(vals.d[5], 29), get_bit(vals.b[4], 29)),
		(get_bit(vals.d[5], 32), get_bit(vals.b[4], 32)),
		(get_bit(vals.c[5], 26), get_bit(vals.d[5], 26)),
		(get_bit(vals.c[5], 27), get_bit(vals.d[5], 27)),
		(get_bit(vals.c[5], 29), get_bit(vals.d[5], 29)),
		(get_bit(vals.c[5], 30), get_bit(vals.d[5], 30)),
		(get_bit(vals.c[5], 32), get_bit(vals.d[5], 32)),
		// unimplemented
		(get_bit(vals.b[5], 29), get_bit(vals.c[5], 29)),
		(get_bit(vals.b[5], 30), 1 << 29),
		(get_bit(vals.b[5], 32), 0),
		(get_bit(vals.a[6], 29), 1 << 28),
		(get_bit(vals.a[6], 32), 1 << 31),
		(get_bit(vals.d[6], 29), get_bit(vals.b[5], 29)),
		(get_bit(vals.c[6], 29), get_bit(vals.d[6], 29)),
		(get_bit(vals.c[6], 30), get_bit(vals.d[6], 30) ^ (1 << 29)),
		(get_bit(vals.c[6], 32), get_bit(vals.d[6], 32) ^ (1 << 31)),
		// I haven't implemented round 3 so these don't exist
		(get_bit(vals.b[9], 32), 1 << 31),
		(get_bit(vals.a[10], 32), 1 << 31),
	];
	

	constraints.iter().fold(0, |sum, (a,b)| sum + (( a == b) as u32 ))
}


fn main() {
	let h: [u32; 4] = [
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476,
	];

	// try to find a collision
	let mut counter: u64 = 0;
	let range = Uniform::new_inclusive(0, 0xFFFF_FFFFu32);
	let mut rand_msg = rand::thread_rng().sample_iter(&range).take(16).collect::<Vec<u32>>();

	loop {
		// construct a message so we can create a collision
		let (m, vals) = modify_first_round(&rand_msg, &h);
		let (m, _) = modify_second_round(m, vals);

		// now construct the sister message m'
		let mut m_prime = m.clone();
		m_prime[1] = (1u32 << 31).wrapping_add(m_prime[1]);
		m_prime[2] = ( (1u32<< 31) - (1 << 28) ).wrapping_add(m_prime[2]);
		m_prime[12] = ( 0xFFFF_0000u32 ).wrapping_add(m_prime[12]);
		
		//let msg2 = modify_first_round(&rand_msg, &h);
		let (h1, vals) = md4(u32s_to_bytes(&m));
		let (h2, _) = md4(u32s_to_bytes(&m_prime));
		let constraints = check_constraints(vals);

		if h1 == h2 {
			println!("Collision!");
			println!("Message 1: {}", m.iter().map(|x| format!("{:08x}", x)).collect::<Vec<String>>().join(" "));
			println!("Hash 1: {}", fmt_hash(&h1));
			println!("Message 2: {}", m_prime.iter().map(|x| format!("{:08x}", x)).collect::<Vec<String>>().join(" "));
			println!("Hash 2: {}", fmt_hash(&h2));
			break;
		}
		counter = counter + 1;
		rand_msg = rand::thread_rng().sample_iter(&range).take(16).collect::<Vec<u32>>();
		println!("{} | {}/121", counter, constraints);
	}
}

