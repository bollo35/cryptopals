extern crate ooga;
use ooga::dsa;
use ooga::byte_utils::ToHexString;

extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};
use openssl::sha::sha1;
use std::fs::File;
use std::io::Read;

struct SignedMessage {
	r: BigNum,
	s: BigNum,
	m: BigNum,
}

fn find_pairs(msgs: &Vec<SignedMessage>) -> Vec<(usize, usize)> {
	let mut ret = Vec::new();
	for i in 0..msgs.len() {
		for j in 1..msgs.len() {
			if msgs[i].r == msgs[j].r && i != j {
				ret.push( (i, j) );
			}
		}
	}
	ret
}

// I prefered to calculate x directly instead of finding k first
//      s1*m2 - s2*m1
//  x = ------------- mod q
//      s2*r1 - s1*r2
fn find_x(m1: &SignedMessage, m2: &SignedMessage,q: &BigNum) -> BigNum {
	let mut bnctx = BigNumContext::new().unwrap();
	let mut temp0 = BigNum::new().unwrap();
	let mut temp1 = BigNum::new().unwrap();

	temp0.mod_mul(&m1.s, &m2.m, q, &mut bnctx).unwrap();
	temp1.mod_mul(&m1.m, &m2.s, q, &mut bnctx).unwrap();
	
	let mut numerator = BigNum::new().unwrap();
	numerator.mod_sub(&temp0, &temp1, q, &mut bnctx).unwrap();

	temp0.mod_mul(&m1.r, &m2.s, q, &mut bnctx).unwrap();
	temp1.mod_mul(&m1.s, &m2.r, q, &mut bnctx).unwrap();
	let mut denominator = BigNum::new().unwrap();
	denominator.mod_sub(&temp0, &temp1, q, &mut bnctx).unwrap();

	// invert the denominator...
	temp0.mod_inverse(&denominator, q, &mut bnctx).unwrap();
	
	temp1.mod_mul(&numerator, &temp0, q, &mut bnctx).unwrap();

	temp1
}

fn main() {
	let mut f = File::open("44.txt").unwrap();
	let mut contents = String::new();
	f.read_to_string(&mut contents).unwrap();

	let data = contents.lines().map(|x| {
			let index = x.find(" ").unwrap() + 1;
			x[index..].to_string()
		}).collect::<Vec<String>>();

	let mut msgs : Vec<SignedMessage> = Vec::with_capacity(contents.lines().count());
	for msg in data.chunks(4) {
		let s = BigNum::from_dec_str(&msg[1]).unwrap();
		let r = BigNum::from_dec_str(&msg[2]).unwrap();
		let m = BigNum::from_hex_str(&msg[3]).unwrap();
		let signed_msg = SignedMessage {
			r: r,
			s: s,
			m: m,
		};
		msgs.push(signed_msg);
	}

	let y = BigNum::from_hex_str("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821").unwrap();
	let dsa_params = dsa::gen_params();

	let pairs = find_pairs(&msgs);

	let mut temp = BigNum::new().unwrap();
	let mut bnctx = BigNumContext::new().unwrap();
	let sha_of_pk = "ca8f6f7c66fa362d40760d135b763eb8527d3d52";
	for (i, j) in pairs {
		let x = find_x(&msgs[i], &msgs[j], &dsa_params.q);
		let hex_str = x.to_vec().to_hex_string();
		let sha = sha1(&hex_str.as_bytes()).to_hex_string();
		println!("SHA(x): {}", sha);
		println!("SHA(x) == {}? {}", sha_of_pk, sha == sha_of_pk);

		temp.mod_exp(&dsa_params.g, &x, &dsa_params.p, &mut bnctx).unwrap();

		let got_it = temp  == y;
		println!("y_p == y? {}", got_it);
		if got_it {
			println!("x: {}", x);
			break;
		}
	}
}

