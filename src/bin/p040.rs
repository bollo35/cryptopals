extern crate ooga;
use ooga::rsa::Rsa;
extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};
use std::ops::{Add, Div, Mul, Sub};

fn main() {
	let rsa0 = Rsa::new();
	let rsa1 = Rsa::new();
	let rsa2 = Rsa::new();

	let msg = "Never gonna give you up! Never gonna let you down!".to_string();

	let ct0 = BigNum::from_slice(&rsa0.enc_str(msg.clone()).unwrap()).unwrap();
	let ct1 = BigNum::from_slice(&rsa1.enc_str(msg.clone()).unwrap()).unwrap();
	let ct2 = BigNum::from_slice(&rsa2.enc_str(msg.clone()).unwrap()).unwrap();

	let og = bncbrt(BigNum::from_slice(&ct0.to_vec()).unwrap());
	println!("og: {:?}", String::from_utf8(og.to_vec()));

	println!("C0: {:?}", ct0);
	println!("C1: {:?}", ct1);
	println!("C2: {:?}", ct2);
	println!();
	println!();
	println!();

	let (e0, n0) = rsa0.get_pubkey();
	let (e1, n1) = rsa1.get_pubkey();
	let (e2, n2) = rsa2.get_pubkey();

	println!("n0 == n1: {}", n0 == n1);
	println!("n2 == n1: {}", n2 == n1);
	println!("n0 == n2: {}", n0 == n2);

	println!("e0: {}", e0);
	println!("e1: {}", e1);
	println!("e2: {}", e2);

	// N0 = n1 * n2
	let N0 = n1.mul(&n2);

	// N1 = n0 * n2
	let N1 = n0.mul(&n2);

	// N2 = n0 * n1
	let N2 = n0.mul(&n1);

	let mut bnctx = BigNumContext::new().unwrap();
	// a0 = invmod(N0, n0)
	let mut a0 = BigNum::new().unwrap();
	a0.mod_inverse(&N0, &n0, &mut bnctx).unwrap();

	// a1 = invmod(N1, n1)
	let mut a1 = BigNum::new().unwrap();
	a1.mod_inverse(&N1, &n1, &mut bnctx).unwrap();

	// a2 = invmod(N2, n2)
	let mut a2 = BigNum::new().unwrap();
	a2.mod_inverse(&N2, &n2, &mut bnctx).unwrap();

	// p0 = c0 * N0 * a0
	let p0 = ct0.mul(&N0).mul(&a0);
	// p1 = c1 * N1 * a1
	let p1 = ct1.mul(&N1).mul(&a1);
	// p2 = c2 * N2 * a2
	let p2 = ct2.mul(&N2).mul(&a2);

	// In the instructions, they say that you don't need to take the result
	// modulo N_012 but that doesn't make sense.
	// The interesting thing is that if you have a message that's smaller
	// than N, and you know e = 3, you could just take the cubed root
	// without the chinese remainder theorem. I don't quite get the point
	// of this exercise. Ah, I guess the only thing I can think of is if
	// you have a message that gets broken into chunks, then you could
	// do this still? I don't know.
	let mut m_e = BigNum::new().unwrap();
	m_e.mod_add(&p0.add(&p1), &p2, &n0.mul(&n1).mul(&n2), &mut bnctx).unwrap();
	println!("m^e: {}", m_e);

	let m = bncbrt(BigNum::from_slice(&m_e.to_vec()).unwrap());

	let m_3 = m.mul(&m).mul(&m);

	if m != m_e {
		println!("m_e - m'_3 = {}", m_e.sub(&m_3));
	}

	let msg = String::from_utf8(m.to_vec());

	println!("Recovered message: {:?}", msg);
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
