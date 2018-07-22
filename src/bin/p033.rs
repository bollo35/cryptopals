extern crate openssl;

use openssl::bn::{BigNum, BigNumContext};

extern crate rand;
use rand::Rng;

fn main() {
	let mut rng = rand::thread_rng();

	let p = BigNum::from_hex_str("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff").unwrap();

	let g = BigNum::from_u32(2).unwrap();

	let a = BigNum::from_u32(rng.gen::<u32>()).unwrap();
	let b = BigNum::from_u32(rng.gen::<u32>()).unwrap();

	let mut bnctx = BigNumContext::new().unwrap();
	// generate our public keys
	let mut A = BigNum::new().unwrap();
	A.mod_exp(&g, &a, &p, &mut bnctx).expect("Unable to calculate A");
	let mut B = BigNum::new().unwrap();
	B.mod_exp(&g, &b, &p, &mut bnctx).expect("Unable to calculate B");
	
	let mut sa = BigNum::new().unwrap();
	sa.mod_exp(&B, &a, &p, &mut bnctx).expect("Unable to calculate the secret key for Alice");
	let mut sb = BigNum::new().unwrap();
	sb.mod_exp(&A, &b, &p, &mut bnctx).expect("Unable to calculate the secret key for Bob");

	println!("sa == sb? {}", sa == sb);
}
