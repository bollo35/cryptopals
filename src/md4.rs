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

pub fn md4(msg: Vec<u8>) -> [u32; 4] {
	let h: [u32; 4] = [
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476,
	];
	md4_attack(msg, h, 0)
}

pub fn md4_attack(msg: Vec<u8>, h: [u32; 4], additional_len: usize) -> [u32; 4] {
	let msg = bytes_to_u32s(pad(msg, additional_len));
	let mut a = h[0];
	let mut b = h[1];
	let mut c = h[2];
	let mut d = h[3];

	// process in 16 word chunks (512 bit)
	for chunk in msg.chunks(16) {
		let x = chunk.clone();
		let aa = a;
		let bb = b;
		let cc = c;
		let dd = d;

		// ROUND 1!
		a = round1(a, b, c, d, x[0] , 3);
		d = round1(d, a, b, c, x[1] , 7);
		c = round1(c, d, a, b, x[2] , 11);
		b = round1(b, c, d, a, x[3] , 19);
		a = round1(a, b, c, d, x[4] , 3);
		d = round1(d, a, b, c, x[5] , 7);
		c = round1(c, d, a, b, x[6] , 11);
		b = round1(b, c, d, a, x[7] , 19);
		a = round1(a, b, c, d, x[8] , 3);
		d = round1(d, a, b, c, x[9] , 7);
		c = round1(c, d, a, b, x[10], 11);
		b = round1(b, c, d, a, x[11], 19);
		a = round1(a, b, c, d, x[12], 3);
		d = round1(d, a, b, c, x[13], 7);
		c = round1(c, d, a, b, x[14], 11);
		b = round1(b, c, d, a, x[15], 19);


		// ROUND 2!
		a = round2(a, b, c, d, x[0] , 3);
		d = round2(d, a, b, c, x[4] , 5);
		c = round2(c, d, a, b, x[8] , 9);
		b = round2(b, c, d, a, x[12], 13);
		a = round2(a, b, c, d, x[1] , 3);
		d = round2(d, a, b, c, x[5] , 5);
		c = round2(c, d, a, b, x[9] , 9);
		b = round2(b, c, d, a, x[13], 13);
		a = round2(a, b, c, d, x[2] , 3);
		d = round2(d, a, b, c, x[6] , 5);
		c = round2(c, d, a, b, x[10], 9);
		b = round2(b, c, d, a, x[14], 13);
		a = round2(a, b, c, d, x[3] , 3);
		d = round2(d, a, b, c, x[7] , 5);
		c = round2(c, d, a, b, x[11], 9);
		b = round2(b, c, d, a, x[15], 13);

		// ROUND 3!
		a = round3(a, b, c, d, x[0] , 3);
		d = round3(d, a, b, c, x[8] , 9);
		c = round3(c, d, a, b, x[4] , 11);
		b = round3(b, c, d, a, x[12], 15);
		a = round3(a, b, c, d, x[2] , 3);
		d = round3(d, a, b, c, x[10], 9);
		c = round3(c, d, a, b, x[6] , 11);
		b = round3(b, c, d, a, x[14], 15);
		a = round3(a, b, c, d, x[1] , 3);
		d = round3(d, a, b, c, x[9] , 9);
		c = round3(c, d, a, b, x[5] , 11);
		b = round3(b, c, d, a, x[13], 15);
		a = round3(a, b, c, d, x[3] , 3);
		d = round3(d, a, b, c, x[11], 9);
		c = round3(c, d, a, b, x[7] , 11);
		b = round3(b, c, d, a, x[15], 15);
		
		a = a.wrapping_add(aa);
		b = b.wrapping_add(bb);
		c = c.wrapping_add(cc);
		d = d.wrapping_add(dd);
	}
	[a.to_be(), b.to_be(), c.to_be(), d.to_be()]
}

#[cfg(test)]
mod test {
	#[test]
	fn md4_hash_check() {
		let hash = md4(b"".to_vec());
		assert_eq!("31d6cfe0d16ae931b73c59d7e0c089c0", fmt_hash(&hash));
		let hash = md4(b"a".to_vec());
		assert_eq!("bde52cb31de33e46245e05fbdbd6fb24", fmt_hash(&hash));
		let hash = md4(b"abc".to_vec());
		assert_eq!("a448017aaf21d8525fc10ae87aa6729d", fmt_hash(&hash));
		let hash = md4(b"message digest".to_vec());
		assert_eq!("d9130a8164549fe818874806e1c7014b", fmt_hash(&hash));
		let hash = md4(b"abcdefghijklmnopqrstuvwxyz".to_vec());
		assert_eq!("d79e1c308aa5bbcdeea8ed63df412da9", fmt_hash(&hash));
		let hash = md4(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec());
		assert_eq!("043f8582f241db351ce627e153e7f0e4", fmt_hash(&hash));
		let hash = md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890".to_vec());
		assert_eq!("e33b4ddc9c38f2199c3e7b164fcc0536", fmt_hash(&hash));
	}
}
