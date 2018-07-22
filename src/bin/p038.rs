extern crate ooga;
use ooga::byte_utils::ToHexString;
use ooga::hmac::hmac_sha256;

extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};
use openssl::sha::{Sha256, sha256};

extern crate rand;
use rand::Rng;
use rand::distributions::Range;

use std::ops::{Add, Sub, Mul};
use std::fs::File;
use std::io::Read;


struct Server {
	// things agreed upon
	nist_prime: BigNum,
	g: BigNum,

	// server generated
	salt: BigNum,
	v: BigNum,
	hmac: Option<String>,
}

impl Server {
	// (1) S
	// x = SHA256(salt|password)
	//     v = g**x % N
	fn new(nist_prime: BigNum, g: u32, password: String) -> Server {

		let g = BigNum::from_u32(g).unwrap();

		let salt = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();

		// x = sha256( salt | password );
		let x = { 
			let mut hasher = Sha256::new();
			hasher.update(&salt.to_vec());
			hasher.update(password.as_bytes());
			let hash = hasher.finish();
			let hash_str = hash.to_hex_string();
			BigNum::from_hex_str(hash_str.as_str()).unwrap()
		};

		// v = g**x mod nist_prime
		let mut bnctx = BigNumContext::new().unwrap();
		let mut v = BigNum::new().unwrap();
		v.mod_exp(&g, &x, &nist_prime, &mut bnctx).unwrap();

		Server {
			nist_prime: nist_prime,
			g: g,
			salt: salt,
			v: v,
			hmac: None,
		}
	}

	// (2) C->S: Send I, A=g**a % N
	// (3) S->: (salt, B = g**b % N, u <random 128-bit number>)
	pub fn recv(&mut self, email: String, a: BigNum) -> (BigNum, BigNum, BigNum) {
		let little_b = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
		let mut bnctx = BigNumContext::new().unwrap();

		// B = g**b % N
		let mut b = BigNum::new().unwrap();
		b.mod_exp(&self.g, &little_b, &self.nist_prime, &mut bnctx).unwrap();
		let random_bytes = rand::thread_rng().gen_iter::<u8>()
		       .take(16)
		       .collect::<Vec<u8>>();
		let u = BigNum::from_slice(&random_bytes).unwrap();

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

		let hmac = hmac_sha256(&k, &self.salt.to_vec());
		self.hmac = Some(hmac);


		(BigNum::from_slice(&self.salt.to_vec()).unwrap(), b, u)
	}

	pub fn validate(&self, hmac: String) -> String {
		let hmacsha256 = self.hmac.as_ref().unwrap();
		println!("Server's hmac: {}", hmacsha256);
		println!("Client's hmac: {}", hmac);
		if hmac.eq(hmacsha256) {
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
	little_a: Option<BigNum>,
	hmac: Option<String>,
}

impl Client {
	fn new(nist_prime: BigNum, g: u32, password: String) -> Client {
		Client {
			email: "email@server.com".to_string(),
			password: password,
			nist_prime: nist_prime,
			g: BigNum::from_u32(g).unwrap(),
			little_a: None,
			hmac: None,
		}
	}

	// send I (email), A = g**a % N
	pub fn send_email_A(&mut self) -> (String, BigNum) {
		let little_a = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
		let mut bnctx = BigNumContext::new().unwrap();
		let mut a = BigNum::new().unwrap();
		a.mod_exp(&self.g, &little_a, &self.nist_prime, &mut bnctx).unwrap();
		self.little_a = Some(little_a);
		(self.email.clone(), a)
	}

	// receive (salt, B, u)
	pub fn recv(&mut self, salt: BigNum, b: BigNum, u: BigNum) {
		// x = sha256( salt | password );
		let x = { 
			let mut hasher = Sha256::new();
			hasher.update(&salt.to_vec());
			hasher.update(self.password.as_bytes());
			let hash = hasher.finish();
			let hash_str = hash.to_hex_string();
			BigNum::from_hex_str(hash_str.as_str()).unwrap()
		};

		let mut bnctx = BigNumContext::new().unwrap();
		// exp = u*x + a
		let exp = u.mul(&x).add(self.little_a.as_ref().unwrap());
		let mut s = BigNum::new().unwrap();
		// S = b ** (u*x + a) mod N
		s.mod_exp(&b, &exp, &self.nist_prime, &mut bnctx).unwrap();

		let key = sha256(&s.to_vec()).to_vec();
		self.hmac = Some( hmac_sha256(&key.to_vec(), &salt.to_vec()) );
	}

	pub fn send_hmac(&self) -> String {
		self.hmac.as_ref().unwrap().clone()
	}

}

fn main() {

	// open word list and choose a random password
	let mut f = File::open("words_alpha.txt").expect("Unable to open `words_alpha.txt`");
	let mut contents = String::new();
	f.read_to_string(&mut contents).expect("Couldn't read `words_alpha.txt` to String");

	let choices = contents.lines().count();
	let choice_index = rand::sample(&mut rand::thread_rng(), 0..choices, 1)[0];
	let password = contents.lines().nth(choice_index).unwrap();
	
	println!("Our chosen password: {}", password);

	println!("Total number of words: {}", contents.lines().count());
	let nist_prime = BigNum::from_hex_str("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").unwrap();

	let g = 2;

	let mut server = Server::new(BigNum::from_slice(&nist_prime.to_vec()).unwrap(), g, password.to_string());
	let mut client = Client::new(BigNum::from_slice(&nist_prime.to_vec()).unwrap(), g, password.to_string());

	// step 1: client sends email, A=g**a % N
	let (email, a) = client.send_email_A();

	// MITM TIME!
	let mitm_a = BigNum::from_slice(&a.to_vec()).unwrap();

	// step 2: server send salt, B = g**b % N, u = 128bit random number
	//         also go ahead and compute the key
	let (salt, b, u) = server.recv(email, a);

	// MAN IN THE MIDDLE TIME YO!
	let b = BigNum::from_u32(2).unwrap();
	let u = BigNum::from_u32(1).unwrap();
	// hold on to the salt, we'll need this later
	let mitm_salt = salt.to_vec();

	// step 3: compute x, S, and the K
	//         and the hmac
	client.recv(salt, BigNum::from_slice(&b.to_vec()).unwrap(), u);

	// step 4: calculate the hmac!
	let hmac = client.send_hmac();

	// MAN IN THE MIDDLE TIME AGAIN!
	// we're going to need this for later
	let hmac_copy = hmac.clone();

	// step 5: server validates the hmac
	let response = server.validate(hmac);

	println!("Server's response: {}", response);
	
	// Time to do some cracking!
	// brute force yo!
	// since we set B = g and u = 1:
	//     S = g**(a+ux) mod N
	//       = A * g**ux mod N
	//       = A * g**x mod N
	// We know how to calculate x, the key,
	// and the HMACSHA256...try all the combinations

	let mut to_hash : Vec<u8> = Vec::with_capacity(50);
	let mut to_hash = mitm_salt.clone();
	let salt_len = mitm_salt.len();

	let mut s = BigNum::new().unwrap();
	let mut t = BigNum::new().unwrap();
	let mut bnctx = BigNumContext::new().unwrap();
	let g = BigNum::from_u32(g).unwrap();
	for password in contents.lines() {
		let password = password.trim();
		println!("Trying: {}", password);
		to_hash.extend_from_slice(password.as_bytes());
		// x = sha256( salt | password );
		let x = { 
			let hash = sha256(&to_hash);
			let hash_str = hash.to_hex_string(); 
			BigNum::from_hex_str(hash_str.as_str()).unwrap()
		};

		// S = A * g**x mod N
		t.mod_exp(&g, &x, &nist_prime, &mut bnctx).unwrap();
		s.mod_mul(&mitm_a, &t, &nist_prime, &mut bnctx).unwrap();

		// K = sha256(s)
		let key = sha256(&s.to_vec()).to_vec();

		let hmac = hmac_sha256(&key, &mitm_salt);

		if hmac == hmac_copy {
			println!("Found the password: {}", password);
			break;
		}

		// clear out the guessed password
		to_hash.truncate(salt_len);
	}
}
