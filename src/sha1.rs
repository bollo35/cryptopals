use std::mem;
// 0 <= t <= 19
#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
	(x & y) ^ (!x & z)
}

// 20 <= t <= 39
// 60 <= t <= 79
#[inline]
fn parity(x: u32, y: u32, z: u32) -> u32 {
	x ^ y ^ z
}

// 40 <= t <= 59
#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
	(x & y) ^ (x & z) ^ (y & z)
}

// 0 <= t <= 19
const K0 : u32 = 0x5a827999;
// 20 <= t <= 39
const K1 : u32 = 0x6ed9eba1;
// 60 <= t <= 79
const K2 : u32 = 0x8f1bbcdc;
// 40 <= t <= 59
const K3 : u32 = 0xca62c1d6;

fn pad(mut msg: Vec<u8>, additional_len: usize) -> Vec<u8> {
	let l = msg.len() * 8;
	msg.push(0x80); // append the 1 (along with 7 zeroes)
	
	// we subtract 8 to account for the 0x80 byte appended
	let k = 448usize.wrapping_sub(l % 512).wrapping_sub(8) % 512;
	let bytes = k / 8 + if k%8 > 0 { 1 } else { 0 };
	msg.append(&mut vec![0; bytes]);
	let total_len = additional_len * 8 + l;
	let len64b = unsafe { mem::transmute::<u64, [u8; 8]>( (total_len as u64).to_be()) };
	msg.extend_from_slice(&len64b[..]);

	msg
}

fn bytes_to_u32s(msg: Vec<u8>) -> Vec<u32> {
	assert!(msg.len() % 16 == 0);
	msg.chunks(4).fold(Vec::with_capacity(msg.len()/4 + 1), | mut acc, curr | { 
		let data = unsafe {mem::transmute::<[u8; 4],u32>([curr[0], curr[1], curr[2], curr[3]])};
		acc.push(data.to_be());
		acc
	})
}

pub fn sha1(msg: Vec<u8>) -> [u32; 5] /*String*/ {
	let h : [u32; 5] = [
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476,
		0xc3d2e1f0,
	];
	sha1_attack(msg, h, 0)
}

pub fn sha1_attack(msg: Vec<u8>, mut h: [u32; 5], additional_len: usize) -> [u32; 5] /*String*/ {
	let padded_msg = bytes_to_u32s(pad(msg, additional_len));
	let mut message_schedule = vec![0u32; 80];

	// 512 bit chunks = 16 32-bit words
	for chunk in padded_msg.chunks(16) {
		// (1) initialize the message schedule
		for (sched, msg) in message_schedule.iter_mut().zip(chunk.iter()) {
			*sched = *msg;
		}

		for t in 16..80 {
			message_schedule[t] = (message_schedule[t-3] ^ message_schedule[t-8] ^ message_schedule[t-14] ^ message_schedule[t-16]).rotate_left(1);
		}

		// (2) initialize the working variables
		let mut a = h[0];
		let mut b = h[1];
		let mut c = h[2];
		let mut d = h[3];
		let mut e = h[4];

		// (3) do the thing...
		for t in 0..80 {
			let (f, k) = match t {
				 0...19 => (ch(b, c, d)    , K0),
				20...39 => (parity(b, c, d), K1),
				40...59 => (maj(b, c, d)   , K2),
				60...79 => (parity(b, c, d), K3),
				_ => panic!("This should be unreachable"),
			};
			let T = a.rotate_left(5)
			         .wrapping_add(f)
			         .wrapping_add(e)
			         .wrapping_add(k)
			         .wrapping_add(message_schedule[t]);
			e = d;
			d = c;
			c = b.rotate_left(30);
			b = a;
			a = T;
		}

		// (4) compute the ith intermediate hash value Hi
		h[0] = h[0].wrapping_add(a);
		h[1] = h[1].wrapping_add(b);
		h[2] = h[2].wrapping_add(c);
		h[3] = h[3].wrapping_add(d);
		h[4] = h[4].wrapping_add(e);
	}
	h
	//format!("{:08x}{:08x}{:08x}{:08x}{:08x}",h[0], h[1], h[2], h[3], h[4])
}

pub fn fmt_hash(h: &[u32; 5]) -> String {
	format!("{:08x}{:08x}{:08x}{:08x}{:08x}",h[0], h[1], h[2], h[3], h[4])
}

pub fn hash_to_vec(h: &[u32; 5]) -> Vec<u8> {
	h.iter().fold(Vec::with_capacity(20), |mut acc, x| {
		acc.push( ((x & 0xFF000000) >> 24) as u8 );
		acc.push( ((x & 0x00FF0000) >> 16) as u8 );
		acc.push( ((x & 0x0000FF00) >>  8) as u8 );
		acc.push( (x & 0x000000FF) as u8 );
		acc
	})
}

/*
fn main() {
	println!("This is a test!");
	//let hash = sha1(b"The quick brown fox jumps over the lazy dog".to_vec());
	let hash = sha1(Vec::new());
	for h in hash.iter() {
		print!("{:08x}", h);
	}
	println!("");
}
*/
