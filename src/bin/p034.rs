extern crate ooga;
use ooga::cipher_utils::{cbc_encrypt, cbc_decrypt};
use ooga::sha1::sha1;
use ooga::byte_utils::ToByteVector;

extern crate openssl;
use openssl::bn::{BigNum, BigNumRef, BigNumContext};

extern crate rand;
use rand::Rng;

struct Initiator {
	power: BigNum,
	shared_key: Vec<u8>,
	p: BigNum,
	g: BigNum,
}

impl Initiator {
	fn new() -> Initiator {
		let p = BigNum::from_hex_str("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").unwrap();

		let g = BigNum::from_u32(2).unwrap();
		let a = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();

		Initiator {
			power: a,
			shared_key: Vec::with_capacity(16),
			p: p,
			g: g,
		}
	}

	/// generate and 'send' the public key
	pub fn initiate(&self) -> (BigNum, BigNum, BigNum) {
		let mut bnctx = BigNumContext::new().unwrap();
		let mut A = BigNum::new().unwrap();
		A.mod_exp(&self.g, &self.power, &self.p, &mut bnctx).expect("Unable to calculate A");
		(BigNum::from_slice(&self.p.to_vec()).unwrap(), BigNum::from_slice(&self.g.to_vec()).unwrap(), A)
	}

	pub fn accept_pubkey(&mut self, b: &BigNumRef) {
		let mut bnctx = BigNumContext::new().unwrap();
		let mut computed_key = BigNum::new().unwrap();
		computed_key.mod_exp(b, &self.power, &self.p, &mut bnctx).expect("Unable to calculate shared key");

		// DEBUG
		println!("Alice computed key: {}", computed_key.to_hex_str().unwrap());
		
		let hash = sha1(computed_key.to_vec()).to_byte_vec();
		self.shared_key = hash[..16].to_vec();
	}

	fn send_msg(&self, msg: &[u8]) -> Result<Vec<u8>,&'static str> {
		if self.shared_key.is_empty() {
			return Err("Must complete key exchange before sending messages");
		}
		// generate a random IV
		let mut iv = rand::thread_rng().gen_iter::<u8>().take(16).collect::<Vec<u8>>();
		let mut enc = cbc_encrypt(&self.shared_key[..], &iv[..], msg);
		enc.append(&mut iv);
		Ok(enc)
	}

	fn dec_msg(&self, enc: Vec<u8>) {
		let iv_start = enc.len() - 16;
		let iv = &enc[enc.len()-16..];
		let dec = cbc_decrypt(&self.shared_key[..], iv, &enc[..iv_start]).unwrap();
		println!("Initiator received: {}", String::from_utf8(dec).unwrap());
	}
}

struct NonInitiator {
	shared_key: Vec<u8>,
}

impl NonInitiator {
	fn new(p: BigNum, g: BigNum, pubkey: BigNum) -> (NonInitiator, BigNum) {
		let b = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
		let mut bnctx = BigNumContext::new().unwrap();
		let mut B = BigNum::new().unwrap();
		B.mod_exp(&g, &b, &p, &mut bnctx).expect("Unable to calculate B");
		
		// calculate shared key
		let mut computed_key = BigNum::new().unwrap();
		computed_key.mod_exp(&pubkey, &b, &p, &mut bnctx).expect("Unable to compute shared key");

		let hash = sha1(computed_key.to_vec()).to_byte_vec();
		let noni = NonInitiator { shared_key: hash[..16].to_vec() };
		(noni, B)
	}

	fn send_msg(&self, msg: &[u8]) -> Result<Vec<u8>,&'static str> {
		if self.shared_key.is_empty() {
			return Err("Must complete key exchange before sending messages");
		}
		// generate a random IV
		let mut iv = rand::thread_rng().gen_iter::<u8>().take(16).collect::<Vec<u8>>();
		let mut enc = cbc_encrypt(&self.shared_key[..], &iv[..], msg);
		enc.append(&mut iv);
		Ok(enc)
	}

	fn dec_msg(&self, enc: Vec<u8>) {
		let iv_start = enc.len() - 16;
		let iv = &enc[enc.len()-16..];
		let dec = cbc_decrypt(&self.shared_key[..], iv, &enc[..iv_start]).unwrap();
		println!("NonInitiator received: {}", String::from_utf8(dec).unwrap());
	}
}

struct Mitm {
	alice: Initiator,
	bob: NonInitiator,
	shared_key: Vec<u8>,
}

impl Mitm {
	fn new() -> Mitm {
		let mut alice = Initiator::new();
		let (p, g, _) = alice.initiate();
		let pcopy = BigNum::from_slice(&p.to_vec()).unwrap();
		// the next two lines are out of order to avoid making another copy of p
		alice.accept_pubkey(&pcopy);
		let (bob, _) = NonInitiator::new(p, g, pcopy);

		let zero = BigNum::from_u32(0).unwrap();

		let hash = sha1(zero.to_vec()).to_byte_vec();
		let shared_key = &hash[..16];
		Mitm {
			alice: alice,
			bob: bob,
			shared_key: shared_key.to_vec(),
		}
	}

	pub fn alice_to_bob(&self, msg: &[u8]) {
		let enc = self.alice.send_msg(msg).unwrap();
		// decrypt the messages for myself since i'm nosy, hoho!
		let secret = self.dec_msg(enc.clone());
		println!("HOHO: Alice told Bob:\n\t{}", secret);
		// i guess we can call this passing it on to bob?
		self.bob.dec_msg(enc);
	}

	pub fn bob_to_alice(&self, msg: &[u8]) {
		let enc = self.bob.send_msg(msg).unwrap();
		// decrypt the messages for myself since i'm nosy, hoho!
		let secret = self.dec_msg(enc.clone());
		println!("HOHO: Bob told Alice:\n\t{}", secret);
		// i guess we can call this passing it on to bob?
		self.alice.dec_msg(enc);
	}

	fn dec_msg(&self, enc: Vec<u8>) -> String {
		let iv_start = enc.len() - 16;
		let iv = &enc[enc.len()-16..];
		let dec = cbc_decrypt(&self.shared_key[..], iv, &enc[..iv_start]).unwrap();
		String::from_utf8(dec).unwrap()
	}
}
fn main() {
	// MITM Diffe Hellman Exchange
	let mitm = Mitm::new();
	mitm.alice_to_bob(b"Hey Bob!");
	mitm.bob_to_alice(b"Hey Alice!");
}

