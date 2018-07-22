extern crate ooga;
use ooga::rsa::{Rsa, SHA1_ASN1};
use ooga::byte_utils::ToHexString;

extern crate openssl;

use openssl::bn::BigNum;
use openssl::sha::sha1;
use std::ops::{Add, Div, Mul, Sub};

fn main() {
	// ASN.1 info for SHA1 (hex encoded)
	// 30213009 06052B0E 03021A05 000414

	// forge a signature...
	let msg = "hi mom";
	let hash = sha1(&msg.as_bytes());

	// let's make sure that sure signing works first
	let rsa = Rsa::new();
	let mut to_sign = Vec::with_capacity(128);
	// len(hash + asn.1) = 35 bytes
	to_sign.push(0u8);
	to_sign.push(1u8);
	to_sign.append(&mut vec![0xff; 128 - 3 - 35]); // 3 for 2 byte prefix and 1 byte end of padding
	to_sign.push(0u8);
	to_sign.extend_from_slice(&SHA1_ASN1[..]);
	to_sign.extend_from_slice(&hash[..]);
	println!("to_sign length: {}", to_sign.len());

	println!("Generated: {:?}", to_sign.to_hex_string());
	let sig = rsa.dec(to_sign);
	

	let verified = rsa.verify_signature(msg.to_string(), sig.to_vec());
	println!("Verification works: {}", verified);


	// now let's actually try to forge the signature...
	// what do we need?
	// something of the form:
	// 00 01 FF .. FF 00 ASN.1 HASH STUFF

	let fs = 1;
	// 1024-bit key => 128 byte signature
	let mut sig_vec = Vec::with_capacity(128);
	sig_vec.push(0u8);
	sig_vec.push(1);
	for _ in 0..fs {
		sig_vec.push(0xff);
	} // idk how many i should put??
	sig_vec.push(0);
	sig_vec.extend_from_slice(&SHA1_ASN1[..]);
	sig_vec.extend_from_slice(&hash[..]);
	
	let fill = 128 - 3 - SHA1_ASN1.len() - hash.len() - fs;
	sig_vec.append(&mut vec![0x00; fill]);
	println!("sig_vec len: {}", sig_vec.len());
	

	// make a cube root...
	let bn = BigNum::from_slice(&sig_vec).unwrap();
	let cbrt = bncbrt(bn);

	//try to verify!
	// turns out that with a cube root function the upper values get preserved
	// fairly decently. Seems pretty obvious now that I think about...
	let verified = rsa.verify_signature(msg.to_string(), cbrt.to_vec());

	println!("verified? {}", verified);
}

fn bncbrt(n: BigNum) -> BigNum {
	let one = BigNum::from_u32(1).unwrap();
	let two = BigNum::from_u32(2).unwrap();
	// let's do a binary search...
	let mut high = BigNum::from_slice(&n.to_vec()).unwrap();
	let mut low = BigNum::from_u32(0).unwrap();

	let mut guess = high.add(&low).div(&two);

	let mut cube = guess.mul(&guess).mul(&guess);

	while cube != n && high != low {
		if cube > n {
			high = guess.sub(&one);
		} else {
			low = guess.add(&one);
		}
		guess = high.add(&low).div(&two);
		cube = guess.mul(&guess).mul(&guess);
	}
	guess
}
