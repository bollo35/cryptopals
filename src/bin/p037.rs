extern crate ooga;
use ooga::byte_utils::ToHexString;
use ooga::hmac::hmac_sha256;

extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};
use openssl::sha::Sha256;

extern crate rand;
use rand::{Rng};

use std::ops::{Add, Sub, Mul};


struct Server {
	// things agreed upon
	nist_prime: BigNum,
	g: BigNum,
	k: BigNum,

	// server generated
	salt: BigNum,
	v: BigNum,
	key: Option<Vec<u8>>,
}

impl Server {
	// (1) S
	fn new(nist_prime: BigNum, g: u32, k: u32, password: String) -> Server {

		let g = BigNum::from_u32(g).unwrap();
		let k = BigNum::from_u32(k).unwrap();

		let salt = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
		let x = { 
			let mut hasher = Sha256::new();
			hasher.update(&salt.to_vec());
			hasher.update(password.as_bytes());
			let hash = hasher.finish();
			let hash_str = hash.to_hex_string();
			BigNum::from_hex_str(hash_str.as_str()).unwrap()
		};

		let mut bnctx = BigNumContext::new().unwrap();
		let mut v = BigNum::new().unwrap();
		v.mod_exp(&g, &x, &nist_prime, &mut bnctx).unwrap();

		Server {
			nist_prime: nist_prime,
			g: g,
			k: k,
			salt: salt,
			v: v,
			key: None,
		}
	}

	// (2) C->S: Send I, A=g**a % N
	// (3) S->C: Send salt, B = kv + g**b % N
	// (4) S,C: Compute uH = SHA256
	pub fn recv(&mut self, email: String, a: BigNum) -> (BigNum, BigNum) {
		let little_b = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
		let mut bnctx = BigNumContext::new().unwrap();

		// B = kv + g**b % N
		let mut g_b_mN = BigNum::new().unwrap();
		g_b_mN.mod_exp(&self.g, &little_b, &self.nist_prime, &mut bnctx).unwrap();
		let b = self.k.mul(&self.v).add(&g_b_mN);
		let u = {
			let mut hasher = Sha256::new();
			hasher.update(&a.to_vec());
			hasher.update(&b.to_vec());
			let hash = hasher.finish();
			let hash_str = hash.to_hex_string();
			BigNum::from_hex_str(hash_str.as_str()).unwrap()
		};

		// compute S = (A * v**u) ** b % N
		let mut v_u_mN = BigNum::new().unwrap();
		v_u_mN.mod_exp(&self.v, &u, &self.nist_prime, &mut bnctx).unwrap();
		// A * (v**u)%N
		let base = v_u_mN.mul(&a);
		let mut s = BigNum::new().unwrap();
		s.mod_exp(&base, &little_b, &self.nist_prime, &mut bnctx).unwrap();

		// compute k
		let k = {
			let mut hasher = Sha256::new();
			hasher.update(&s.to_vec());
			let hash = hasher.finish();
			hash[..].to_vec()
		};
		self.key = Some(k);


		(BigNum::from_slice(&self.salt.to_vec()).unwrap(), b)
	}

	pub fn validate(&self, hmac: String) -> String {
		let hmacsha256 = hmac_sha256(self.key.as_ref().unwrap(), &self.salt.to_vec());
		println!("Server's hmac: {}", hmacsha256);
		println!("Client's hmac: {}", hmac);
		if hmacsha256 == hmac {
			"OK".to_string()
		} else {
			"NOT OK!".to_string()
		}
	}
}

struct Client {
	// things agreed upon
	email: String,
	password: String,
	nist_prime: BigNum,
	g: BigNum,
	k: BigNum,
	little_a: Option<BigNum>,
	a: Option<BigNum>,
	b: Option<BigNum>,
	u: Option<BigNum>,
	salt: Option<BigNum>,
	key: Option<Vec<u8>>,
}

impl Client {
	fn new(nist_prime: BigNum, g: u32, k: u32) -> Client {
		Client {
			email: "email@server.com".to_string(),
			password: "uberpassvurd!()*#)$(".to_string(),
			nist_prime: nist_prime,
			g: BigNum::from_u32(g).unwrap(),
			k: BigNum::from_u32(k).unwrap(),
			little_a: None,
			a: None,
			b: None,
			u: None,
			salt: None,
			key: None,
		}
	}

	// send I (email), A = g**a % N
	pub fn send_email_A(&mut self) -> (String, BigNum) {
		let little_a = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
		let mut bnctx = BigNumContext::new().unwrap();
		self.little_a = Some(little_a);
		// send A = 0, now I don't need a password! muahahaha!
		let a = BigNum::from_u32(0).unwrap();
		self.a = Some(BigNum::from_slice(&a.to_vec()).unwrap());
		(self.email.clone(), a)
	}

	pub fn recv(&mut self, salt: BigNum, b: BigNum) {
		self.salt = Some(salt);
		let u = {
			let mut hasher = Sha256::new();
			hasher.update(&self.a.as_ref().unwrap().to_vec());
			hasher.update(&b.to_vec());
			let hash = hasher.finish();
			let hash_str = hash.to_hex_string();
			BigNum::from_hex_str(hash_str.as_str()).unwrap()
		};
		self.u = Some(u);
		self.b = Some(b);
	}

	pub fn gen_key(&mut self) {
		let k = {
			let mut hasher = Sha256::new();
			hasher.update(&self.a.as_ref().unwrap().to_vec());
			let hash = hasher.finish();
			hash[..].to_vec()
		};
		self.key = Some(k);
	}

	pub fn send_hmac(&self) -> String {
		let salt = self.salt.as_ref().unwrap();
	
		
		hmac_sha256(&self.key.as_ref().unwrap(), &salt.to_vec())
	}

}

fn main() {
	let nist_prime = BigNum::from_hex_str("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").unwrap();

	let g = 2;
	let k = 3;


	let mut server = Server::new(BigNum::from_slice(&nist_prime.to_vec()).unwrap(), g, k, "uberpassvurd!()*#)$(".to_string());
	let mut client = Client::new(nist_prime, g, k);

	// step 1: client sends email, A=g**a % N
	let (email, a) = client.send_email_A();

	// step 2: server send salt, and B = kv + g**b % N
	//         and do a bunch of other stuff it's supposed to do later
	//         like compute the key
	let (salt, b) = server.recv(email, a);

	// step 3: compute u
	client.recv(salt, b);
	// step 4: compute the key
	client.gen_key();

	// step 5: calculate the hmac!
	let hmac = client.send_hmac();

	// step 6: server validates the hmac
	let response = server.validate(hmac);
	
	println!("Server says: {}", response);
}
