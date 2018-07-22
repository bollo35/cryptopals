extern crate ooga;
use ooga::rsa::Rsa;

extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};
use std::ops::Sub;
use std::collections::HashSet;

struct DecServer {
	rsa: Rsa,
	queries: HashSet<Vec<u8>>,
}

impl DecServer {
	pub fn new() -> DecServer {
		DecServer {
			rsa: Rsa::new(),
			queries: HashSet::new(),
		}	
	}

	pub fn get_ciphertext(&mut self) -> Vec<u8> {
		let secret_message = "I like turtles".to_string();
		let enc = self.rsa.enc_str(secret_message).unwrap();
		// pretend it's already been decrypted
		self.queries.insert(enc.clone());
		enc
	}

	pub fn get_pubkey(&self) -> (BigNum, BigNum) {
		self.rsa.get_pubkey()
	}

	pub fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, &'static str> {
		if self.queries.contains(&ciphertext) {
			return Err("No decryption for you!");
		}
		Ok(self.rsa.dec(ciphertext))
	}
}

fn main() {
	let mut dec_server = DecServer::new();
	let ct = dec_server.get_ciphertext();
	let (e, n) = dec_server.get_pubkey();

	let decryption = dec_server.decrypt(ct.clone());
	// disappointed!
	println!("Decryption! => {:?}", decryption);

	//implement the attack now
	let mut bnctx = BigNumContext::new().unwrap();
	// set s = n - 1
	let s = n.sub(&BigNum::from_u32(1).unwrap());

	// s_e = s**e % n
	let mut s_e = BigNum::new().unwrap();
	s_e.mod_exp(&s, &e, &n, &mut bnctx).unwrap();

	let c = BigNum::from_slice(&ct).unwrap();
	let mut new_ct = BigNum::new().unwrap();
	// new_ct = ((s**e % n) * c) % n
	new_ct.mod_mul(&s_e, &c, &n, &mut bnctx).unwrap();

	let c_prime = new_ct.to_vec();

	let semi_decryption = dec_server.decrypt(c_prime).unwrap();

	let mut inv_s = BigNum::new().unwrap();
	inv_s.mod_inverse(&s, &n, &mut bnctx).unwrap();

	let mut pt = BigNum::new().unwrap();
	// I FORGOT TO DO MODULAR MULTIPLICATION! BAD ME.
	pt.mod_mul(&inv_s, &BigNum::from_slice(&semi_decryption).unwrap(), &n, &mut bnctx).unwrap();
	
	println!("Decryption??? => {:?}", String::from_utf8(pt.to_vec()));
}
