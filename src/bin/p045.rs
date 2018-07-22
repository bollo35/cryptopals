extern crate ooga;
use ooga::dsa;

extern crate openssl;
use openssl::bn::{BigNum, BigNumContext};
use std::ops::Add;

extern crate rand;
use rand::Rng;


fn magic_signature(params: &dsa::DsaParams, y: BigNum) -> (BigNum, BigNum) {
	let mut bnctx = BigNumContext::new().unwrap();
	let z = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
	let mut inv_z = BigNum::new().unwrap();
	inv_z.mod_inverse(&z, &params.q, &mut bnctx).unwrap();

	let mut temp = BigNum::new().unwrap();
	temp.mod_exp(&y, &z, &params.p, &mut bnctx).unwrap();

	let mut r = BigNum::new().unwrap();
	r.nnmod(&temp, &params.q, &mut bnctx).unwrap();

	temp.mod_mul(&r, &inv_z, &params.q, &mut bnctx).unwrap();

	(r, temp)
}

fn main() {
	let mut dsa_params = dsa::gen_params();
	let msg = "I thought about it.";

/*
	// Substitute 0 for g...
	// NB: In order for this to work, we have to alter the
	//     sign_message algorithm to allow r := 0
	//     otherwise, it will just fall into an infinite loop
	let keys = dsa::gen_key_pair(&dsa_params).unwrap();
	dsa_params.g = BigNum::from_u32(0).unwrap();
	let sig = dsa::sign_message(msg.to_string(), &dsa_params, &keys);
	// "You will notice something bad." ==> r = 0.
	println!("signature: {:?}", sig);

	// now verify the signature
	let is_signature_valid = dsa::valid_signature(msg.to_string(), sig, &dsa_params, keys.pubkey());
	println!("Is signature valid? {}", is_signature_valid);
*/

	let temp = dsa_params.p.add(&BigNum::from_u32(1).unwrap());
	// set g = p+1;
	dsa_params.g = temp;
	let keys = dsa::gen_key_pair(&dsa_params).unwrap();

	// we can come up with a magic signature for any public key that will validate against any string
	//       z                         r
	// r =( y  mod p ) mod q      s = --- mod q
	//                                 s
	// first let's sign without using our magic params for curiousity's sake
	let sig = dsa::sign_message(msg.to_string(), &dsa_params, &keys);
	println!("signature: {:?}", sig);

	let is_signature_valid = dsa::valid_signature(msg.to_string(), sig, &dsa_params, keys.pubkey());
	println!("Is signature valid? {}", is_signature_valid);

	let sig = magic_signature(&dsa_params, keys.pubkey());

	let is_signature_valid = dsa::valid_signature("Hello, world.".to_string(), sig, &dsa_params, keys.pubkey());
	println!("Is magic signature valid? {}", is_signature_valid);

	// generate signature for 'Hello, world' and 'Goodbye, world.'");
	let hw_sig = dsa::sign_message("Hello, world".to_string(), &dsa_params, &keys);
	let gw_sig = dsa::sign_message("Goodbye, world".to_string(), &dsa_params, &keys);

	println!("Hello world signature: {:?}", hw_sig);
	println!("Goodbye world signature: {:?}", gw_sig);
}

