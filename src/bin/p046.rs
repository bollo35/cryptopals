extern crate ooga;
use ooga::rsa::Rsa;
use ooga::base64;

extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};
use std::ops::{Add, Div};

fn main() {
	let plaintext = base64::decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==");

	let pt_num = BigNum::from_slice(&plaintext).unwrap();

	let rsa = Rsa::with_pair_bitlength(1024);
	let (e, n) = rsa.get_pubkey();
	let c = rsa.enc(pt_num).unwrap();
	let mut c = BigNum::from_slice(&c).unwrap();

	let odd_oracle = move |cp: &BigNum| {
		// decrypt cp
		let dp = rsa.dec(cp.to_vec());
		let bn = BigNum::from_slice(&dp).unwrap();
		bn.is_bit_set(0)
	};

	let mut factor = BigNum::new().unwrap();
	let mut bnctx = BigNumContext::new().unwrap();
	factor.mod_exp(&BigNum::from_u32(2).unwrap(), &e, &n, &mut bnctx).unwrap();

	let mut high = BigNum::from_slice(&n.to_vec()).unwrap();
	let mut low = BigNum::from_u32(0).unwrap();
	let two = BigNum::from_u32(2).unwrap();


	for _ in 0..1024 {
		let mut temp = BigNum::new().unwrap();
		temp.mod_mul(&c, &factor, &n, &mut bnctx).unwrap();
		c = temp;
		if odd_oracle(&c) {
			low = high.add(&low).div(&two);
		} else {
			high = high.add(&low).div(&two);
		}
	}

	println!("recovered_plaintext: {:?}", String::from_utf8(high.to_vec()));
	println!("recovered_plaintext: {:?}", String::from_utf8(low.to_vec()));
}

