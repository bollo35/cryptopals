extern crate openssl;
extern crate rand;

use openssl::bn::{BigNum, BigNumContext};
use openssl::sha::{sha1};

use self::rand::{Rng, thread_rng};

use std::ops::{Add, Div, Mul, Sub};

pub struct DsaParams {
	pub p: BigNum,
	pub q: BigNum,
	pub g: BigNum,
}

// not really generating parameters
pub fn gen_params() -> DsaParams {
	let p = BigNum::from_hex_str("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1").unwrap();

	let q = BigNum::from_hex_str("f4f47f05794b256174bba6e9b396a7707e563c5b").unwrap();

	let g = BigNum::from_hex_str("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291").unwrap();

	DsaParams {
		p: p,
		q: q,
		g: g,
	}
}

pub struct KeyPair {
	x: BigNum, // private key
	y: BigNum, // public key
}

impl KeyPair {
	pub fn pubkey(&self) -> BigNum {
		BigNum::from_slice(&self.y.to_vec()).unwrap()
	}

	pub fn new(x: BigNum, y: BigNum) -> KeyPair {
		KeyPair { x: x, y: y }
	}
}

pub fn gen_key_pair(params: &DsaParams) -> Result<KeyPair, &'static str> {
	let n = params.q.num_bits() as usize;
	let l = params.p.num_bits() as usize;
	if n != 160 {
		return Err("expected N of 1024 bits");
	} else if l != 1024 {
		return Err("expected L of 160 bits");
	}

	let c_bytes = thread_rng().gen_iter::<u8>().take( (n+64) / 8 ).collect::<Vec<u8>>();
	let c  = BigNum::from_slice(&c_bytes).unwrap();

	let mut bnctx = BigNumContext::new().unwrap();
	let one = BigNum::from_u32(1).unwrap();

	let mut x = BigNum::new().unwrap();
	x.nnmod(&c, &params.q.sub(&one), &mut bnctx).unwrap();
	x = x.add(&one);

	let mut y = BigNum::new().unwrap();
	y.mod_exp(&params.g, &x, &params.p, &mut bnctx).unwrap();

	Ok( KeyPair {x:x , y:y})
}

// returns (k, k^-1)
pub fn gen_subkey_pair(params: &DsaParams) -> (BigNum, BigNum) {
	let n = params.q.num_bits() as usize;
	let c_bytes = thread_rng().gen_iter::<u8>().take( (n+64) / 8 ).collect::<Vec<u8>>();
	let c  = BigNum::from_slice(&c_bytes).unwrap();

	let mut bnctx = BigNumContext::new().unwrap();
	let one = BigNum::from_u32(1).unwrap();

	let mut k = BigNum::new().unwrap();
	k.nnmod(&c, &params.q.sub(&one), &mut bnctx).unwrap();
	k = k.add(&one);
	
	let mut k_inv = BigNum::new().unwrap();
	k_inv.mod_inverse(&k, &params.q, &mut bnctx).unwrap();

	(k, k_inv)
}


// returns (r, s)
pub fn sign_message(msg: String, params: &DsaParams, key_pair: &KeyPair) -> (BigNum, BigNum) {
	let mut r = BigNum::new().unwrap();
	let mut s = BigNum::new().unwrap();

	let hash = sha1(msg.as_bytes()).iter().map(|x| *x).collect::<Vec<u8>>();
	let z = BigNum::from_slice(&hash).unwrap();

	let mut bnctx = BigNumContext::new().unwrap();
	let mut temp = BigNum::new().unwrap();
	let zero = BigNum::from_u32(0).unwrap();

	let mut signed = false;
	while !signed {
		let (k, k_inv) = gen_subkey_pair(params);

		temp.mod_exp(&params.g, &k, &params.p, &mut bnctx).unwrap();
		r.nnmod(&temp, &params.q, &mut bnctx).unwrap();

		temp = z.add(&key_pair.x.mul(&r)).mul(&k_inv);
		s.nnmod(&temp, &params.q, &mut bnctx).unwrap();

		signed = r != zero && s != zero;
	}

	(r, s)
}

pub fn valid_signature(msg: String, sig: (BigNum, BigNum), params: &DsaParams, y: BigNum) -> bool {
	let (r, s) = sig;
	if r.is_negative() || r >= params.q { return false; }
	if s.is_negative() || s >= params.q { return false; }

	let mut bnctx = BigNumContext::new().unwrap();

	let mut w = BigNum::new().unwrap();
	w.mod_inverse(&s, &params.q, &mut bnctx).unwrap();

	let hash = sha1(msg.as_bytes()).iter().map(|x| *x).collect::<Vec<u8>>();
	let z = BigNum::from_slice(&hash).unwrap();

	let mut u1 = BigNum::new().unwrap();
	u1.mod_mul(&z, &w, &params.q, &mut bnctx).unwrap();

	let mut u2 = BigNum::new().unwrap();
	u2.mod_mul(&r, &w, &params.q, &mut bnctx).unwrap();

	let mut temp = BigNum::new().unwrap();
	temp.mod_exp(&params.g, &u1, &params.p, &mut bnctx).unwrap();
	let mut temp1 = BigNum::new().unwrap();
	temp1.mod_exp(&y, &u2, &params.p, &mut bnctx).unwrap();
	let mut temp2 = BigNum::new().unwrap();
	temp2.mod_mul(&temp, &temp1, &params.p, &mut bnctx).unwrap();

	let mut v = BigNum::new().unwrap();
	v.nnmod(&temp2, &params.q, &mut bnctx).unwrap();

	v == r
}


#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn bit_len() {
		let dsa_params = gen_params();
		assert!(dsa_params.p.num_bits() == 1024);
		assert!(dsa_params.q.num_bits() == 160);
	}

	#[test]
	fn check_signing() {
		let dsa_params = gen_params();
		let key_pair = gen_key_pair(&dsa_params).unwrap();
		let msg = "I love bacon".to_string();

		let sig = sign_message(msg.clone(), &dsa_params, &key_pair);

		let valid = valid_signature(msg, sig, &dsa_params, key_pair.pubkey());

		assert!(valid);
	}
}
