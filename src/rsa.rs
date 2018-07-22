extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};
use std::ops::{Mul, Sub};
use openssl::sha::sha1;

use byte_utils::ToHexString;

pub const SHA1_ASN1 : [u8;15] = [0x30, 0x21, 0x30, 0x09, 0x06,
                                 0x05, 0x2B, 0x0E, 0x03, 0x02,
                                 0x1A, 0x05, 0x00, 0x04, 0x14];
pub struct Rsa {
	pubkey: BigNum,
	privkey: BigNum,
	n: BigNum,
	keypair_len: usize,
}

impl Rsa {
	pub fn with_pair_bitlength(bit_length: usize) -> Rsa {
		let mut bnctx = BigNumContext::new().unwrap();

		// generate 2 primes
		// message must be sufficiently shorter than primes
		let mut p = BigNum::new().unwrap();
		p.generate_prime((bit_length/2) as i32, true, None, None).expect("Unable to generate prime p");
		let mut q = BigNum::new().unwrap();
		q.generate_prime((bit_length/2) as i32, true, None, None).expect("Unable to generate prime q");
		
		let one = BigNum::from_u32(1).unwrap();
		let n = p.mul(&q);
		let et = p.sub(&one).mul(&q.sub(&one));
		let e = BigNum::from_u32(3).unwrap();
		let mut d = BigNum::new().unwrap();
		d.mod_inverse(&e, &et, &mut bnctx).unwrap();

		Rsa {
			pubkey: e,
			privkey: d,
			n: n,
			keypair_len: bit_length,
		}
	}

	pub fn new() -> Rsa {
		Rsa::with_pair_bitlength(2048)
	}

	// return [e, n]
	pub fn get_pubkey(&self) -> (BigNum, BigNum) {
		( BigNum::from_slice(&self.pubkey.to_vec()).unwrap(), BigNum::from_slice(&self.n.to_vec()).unwrap() )
	}

	pub fn enc_str(&self, msg: String) -> Result<Vec<u8>,&'static str> {
		let hex_str = msg.into_bytes().to_hex_string();
		let msg = BigNum::from_hex_str(&hex_str).unwrap();
		if msg > self.n {
			return Err("message is too big");
		}
		let mut bnctx = BigNumContext::new().unwrap();
		let mut temp = BigNum::new().unwrap();

		temp.mod_exp(&msg, &self.pubkey, &self.n, &mut bnctx).unwrap();
		Ok(temp.to_vec())
	}

	pub fn enc(&self, msg: BigNum) -> Result<Vec<u8>, &'static str> {
		if msg > self.n {
			return Err("message is too big");
		}
		let mut bnctx = BigNumContext::new().unwrap();
		let mut temp = BigNum::new().unwrap();

		temp.mod_exp(&msg, &self.pubkey, &self.n, &mut bnctx).unwrap();
		Ok(temp.to_vec())
	}

	pub fn dec(&self, ct: Vec<u8>) -> Vec<u8> {
		let ct = BigNum::from_slice(&ct).unwrap();
		let mut bnctx = BigNumContext::new().unwrap();
		let mut temp = BigNum::new().unwrap();

		temp.mod_exp(&ct, &self.privkey, &self.n, &mut bnctx).unwrap();
		temp.to_vec()
	}

	pub fn verify_signature(&self, msg: String, signature: Vec<u8>) -> bool {
		let sig = BigNum::from_slice(&signature).unwrap();
		let mut bnctx = BigNumContext::new().unwrap();
		let mut sig_3 = BigNum::new().unwrap();
		sig_3.mod_exp(&sig, &self.pubkey, &self.n, &mut bnctx).unwrap();

		let mut sig_bytes = vec![0;1];
		sig_bytes.append(&mut sig_3.to_vec());
		if sig_bytes[0] != 0 && sig_bytes[1] != 1 {
			println!("(1) didn't find 1");
			return false;
		}
		let mut i = 2;
		while sig_bytes[i] == 0xff { i = i + 1; }
		if sig_bytes[i] != 0x00 { println!("didn't find zero. Found: {:02x} instead", sig_bytes[i]); return false; }
		i+=1;
		// verify ASN.1
		if sig_bytes[i..i+SHA1_ASN1.len()] != SHA1_ASN1[..] { println!("ASN.1 didn't match"); return false; }
		i += SHA1_ASN1.len();

		// finally we can verify the hash...
		let hash = sha1(msg.as_bytes());
		return hash[..] == sig_bytes[i..(i+hash.len())];
	}

	pub fn keypair_len(&self) -> usize {
		self.keypair_len
	}
}
