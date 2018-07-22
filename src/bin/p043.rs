extern crate ooga;
use ooga::byte_utils::ToHexString;
use ooga::dsa;
extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};
use openssl::sha::sha1;
use std::ops::{Mul, Sub};

fn calculate_x(k: u32, r_inv: &BigNum, s: &BigNum, z: &BigNum, params: &dsa::DsaParams) -> BigNum {
	let k = BigNum::from_u32(k).unwrap();
	let mut bnctx = BigNumContext::new().unwrap();

	let temp = k.mul(s).sub(z).mul(r_inv);
	let mut x =  BigNum::new().unwrap();
	x.nnmod(&temp, &params.q, &mut bnctx).unwrap();

	x
}

fn main() {

	// I'm also not sure why the public key is given. It's not needed for solving this challenge
	// although ideally you could generate the signature and verify you have the right private key
	// LOL...ok so i totally missed it, the solution is to use the private key to calculate the public key
	// which i should have known from implementing DSA...but I was too busy trying ot take in all the info
	// not sure why they gave all that extra stuff that was useless -_-
	let msg = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";
	// first make sure we're generating the correct hash
	let hash = sha1(msg);
	let hash_str = hash.to_hex_string();
	println!("hash: {}", hash_str);
	
	// tricky, tricky - initially i thought these were hex strings
	let r = BigNum::from_dec_str("548099063082341131477253921760299949438196259240").unwrap();
	let s = BigNum::from_dec_str("857042759984254168557880549501802188789837994940").unwrap();

	let z = BigNum::from_hex_str("d2d0714f014a9784047eaeccf956520045c45265").unwrap();

	let dsa_params = dsa::gen_params();
	let mut bnctx = BigNumContext::new().unwrap();
	let mut r_inv = BigNum::new().unwrap();
	r_inv.mod_inverse(&r, &dsa_params.q, &mut bnctx).unwrap();


	let y = BigNum::from_hex_str("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17").unwrap();

	let mut temp = BigNum::new().unwrap();
	for k in 0..65536 {
		let x = calculate_x(k, &r_inv, &s, &z, &dsa_params);

		temp.mod_exp(&dsa_params.g, &x, &dsa_params.p, &mut bnctx).unwrap();
		
		if temp == y {
			println!("found the private key! Huzzah! {}", x);
			let hex_str = x.to_vec().to_hex_string();
			let sha = sha1(&hex_str.as_bytes()).to_hex_string();
			if sha == "0954edd5e0afe5542a4adf012611a91912a3ec16" {
				println!("Indeed we have found the private key!");
				break;
			}
		}

	}
}

