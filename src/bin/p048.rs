extern crate ooga;
use ooga::rsa::Rsa;

extern crate openssl;
use openssl::bn::{BigNum, BigNumContext};
use std::ops::{Add, Div, Mul, Sub};

extern crate rand;
use rand::Rng;

// PKCS#1 v1.5 padding
// 00||02||PS||00||Data
// |Data| <= k - 11 , where k = byte length of the modulus
pub fn pkcs1_pad(mut data: Vec<u8>, byte_len: usize) -> Vec<u8> {
	assert!(data.len() <= byte_len - 11);
	let mut padded = Vec::with_capacity(byte_len);
	padded.push(0);
	padded.push(2);
	
	let pad_len = byte_len - 3 - data.len();
	let mut random_bytes = rand::thread_rng().
	                             gen_iter::<u8>().
	                             filter(|&x| x != 0).
	                             take(pad_len).
	                             collect::<Vec<u8>>();

	padded.append(&mut random_bytes);

	padded.push(0);
	padded.append(&mut data);

	padded
}

fn main() {
	println!("---------[WARNING]---------");
	println!("This takes FOREVER to run!!\n");
	println!("---------------------------");
	let k = 768/8;
	//let k = 256/8;
	let rsa = Rsa::with_pair_bitlength(8*k);
	let c = rsa.enc(BigNum::from_slice(&pkcs1_pad(b"kick it, CC".to_vec(), k)).unwrap()).unwrap();
	let c = BigNum::from_slice(&c).unwrap();

	let (e, n) = rsa.get_pubkey();

	let pkcs1_compliant = move |c: &BigNum| {
		let d = rsa.dec(c.to_vec());
		d.len() == rsa.keypair_len()/8 - 1 && d[0] == 2
	};

	let mut bnctx = BigNumContext::new().unwrap();
	let zero = BigNum::from_u32(0).unwrap();
	let one = BigNum::from_u32(1).unwrap();
	let two = BigNum::from_u32(2).unwrap();
	let three = BigNum::from_u32(3).unwrap();
	let mut B = BigNum::new().unwrap();
	B.exp(&BigNum::from_u32(2).unwrap(),
	      &BigNum::from_u32( 8 * (k - 2) as u32 ).unwrap(),
	      &mut bnctx).unwrap();
	let twoB = B.mul(&two);
	let threeB = B.mul(&three);
//	println!("B: {}", B);

	// --------------------------------------------------
	// STEP 1: Blinding...we don't really need to do this
	// find an integer s0, such that:
	// c0 = c*(s0**e) % n | is PKCS#1 v1.5 compliant
	// --------------------------------------------------
	let mut s0 = BigNum::from_u32(1).unwrap();
	//let mut s0 = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
	let mut temp = BigNum::new().unwrap();
	// temp = s0**e mod n
	temp.mod_exp(&s0, &e, &n, &mut bnctx).unwrap();
	
	let mut c0 = BigNum::new().unwrap();
	c0.mod_mul(&c, &temp, &n, &mut bnctx).unwrap();

	while !pkcs1_compliant(&c0) {
		s0 = BigNum::from_u32(rand::thread_rng().gen::<u32>()).unwrap();
		temp.mod_exp(&s0, &e, &n, &mut bnctx).unwrap();
		c0.mod_mul(&c, &temp, &n, &mut bnctx).unwrap();
	}
//	println!("s0: {}", s0);
	// --------------[STEP 1: END ]----------------------

	// --------------------------------------------------
	// STEP 2a: Starting the search
	// look for s1 >= n/(3B) such that
	// ci = c0*(s1**e) % n | is PKCS#1 v1.5 compliant
	// --------------------------------------------------
	let mut s1 = n.div(&threeB);
	temp.mod_exp(&s1, &e, &n, &mut bnctx).unwrap();
	let mut ci = BigNum::new().unwrap();
	ci.mod_mul(&c0, &temp, &n, &mut bnctx).unwrap();

	while !pkcs1_compliant(&ci) {
		s1 = s1.add(&one);
		temp.mod_exp(&s1, &e, &n, &mut bnctx).unwrap();
		ci.mod_mul(&c0, &temp, &n, &mut bnctx).unwrap();
	}

//	println!("s1: {}", s1);
	// --------------[STEP 2a: END ]---------------------


	let mut intervals = Vec::new();
	intervals.push ( (BigNum::from_slice(&twoB.to_vec()).unwrap(), threeB.sub(&one) ) );
	let mut found = false;
	let mut si = s1;
	while !found {
		if intervals.len() > 1 {
			// --------------------------------------------------
			// STEP 2b: Searching with more than one interval
			//          remaining
			// --------------------------------------------------
//			println!("Multiple intervals");
			si = si.add(&one);
			temp.mod_exp(&si, &e, &n, &mut bnctx).unwrap();
			ci.mod_mul(&temp, &c0, &n, &mut bnctx).unwrap();

			while !pkcs1_compliant(&ci) {
				si = si.add(&one);
				temp.mod_exp(&si, &e, &n, &mut bnctx).unwrap();
				ci.mod_mul(&temp, &c0, &n, &mut bnctx).unwrap();
			}
//			println!("\tsi => {}", si);
		} else if intervals.len() == 1 {
			// --------------------------------------------------
			// STEP 2c: Searching with one interval remaining
			// --------------------------------------------------
//			println!("One interval");
			let (a, b) = intervals.pop().unwrap();
			let rn = b.mul(&si).sub(&twoB).div(&n).mul(&two).mul(&n); // 2*(b*s[i-1] - 2B)/n
			let mut lo = twoB.add(&rn).div(&b); // (2B+r[i]*n)/b
			let mut hi = threeB.add(&rn).div(&a);

			let n_a = n.div(&a);
			let n_b = n.div(&b);

			si = BigNum::from_slice(&lo.to_vec()).unwrap();
		
			temp.mod_exp(&si, &e, &n, &mut bnctx).unwrap();
			ci.mod_mul(&c0, &temp, &n, &mut bnctx).unwrap();

		
			while !pkcs1_compliant(&ci) {
				si = si.add(&one);
				// try another ri
				if si == hi {
					lo = lo.add(&n_b);
					hi = hi.add(&n_a);
					si = BigNum::from_slice(&lo.to_vec()).unwrap(); }
				temp.mod_exp(&si, &e, &n, &mut bnctx).unwrap();
				ci.mod_mul(&c0, &temp, &n, &mut bnctx).unwrap();
			}
			intervals.push( (a, b) );
//			println!("\tsi => {}", si);
		} else {
			panic!("Should always have at least one interval!");
		}
	
		// --------------------------------------------------
		// STEP 3: Narrowing the set of solutions
		// --------------------------------------------------
		let mut new_intervals = Vec::with_capacity(intervals.len());
		for (a, b) in intervals.iter_mut() {
			let lower_r = a.mul(&si).sub(&threeB).add(&one).div(&n); // (a*s[i] - 3B + 1)/n
			let higher_r = b.mul(&si).sub(&twoB).div(&n); // (b*si - 2B)/n
			let mut r = BigNum::from_slice(&lower_r.to_vec()).unwrap();
	
			let a_og = BigNum::from_slice(&a.to_vec()).unwrap();
			let b_og = BigNum::from_slice(&b.to_vec()).unwrap();
			while r <= higher_r && !found {
				let ceil = twoB.add(&r.mul(&n)).add(&si).div(&si);
				*a = if a_og > ceil { BigNum::from_slice(&a_og.to_vec()).unwrap() } else { ceil };
	
				let floor = threeB.sub(&one).add(&r.mul(&n)).div(&si);
				*b = if b_og > floor { floor } else { BigNum::from_slice(&b_og.to_vec()).unwrap() };
				found = a == b;
				if a <= b {
					new_intervals.push( ( BigNum::from_slice(&a.to_vec()).unwrap(), 
					                      BigNum::from_slice(&b.to_vec()).unwrap() ) );
				}
				r = r.add(&one);
			}
			if found { break; }
		}
		intervals = new_intervals;
	}

	// --------------------------------------------------
	// STEP 4: Computing the solution
	// --------------------------------------------------
	let (a, b) = intervals.pop().unwrap();
	temp.mod_inverse(&s0, &n, &mut bnctx).unwrap();
	let mut m = BigNum::new().unwrap();
	m.mod_mul(&a, &temp, &n, &mut bnctx).unwrap();
	println!("m: {}", m);

	let msg = m.to_vec();
	let indx = k - msg.iter().rev().position(|&x| x == 0).unwrap() - 1;
	let og_msg = String::from_utf8(msg[indx..].to_vec());
	println!("OG Message: {:?}", og_msg);
}

