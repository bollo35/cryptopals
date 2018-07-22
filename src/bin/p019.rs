extern crate ooga;
use ooga::base64;
use ooga::cipher_utils::ctr_stream;
use ooga::byte_utils::xor;
extern crate rand;
use rand::Rng;

fn main() {
	let nonce = [0u8; 8];
	let mut rng = rand::thread_rng();
	
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();
	let mut ciphertexts : Vec<Vec<u8>> = [
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	].iter().map(|s| {
		let pt = base64::decode(&s);
		let blocks = pt.len() / 16 + 1;
		let keystream = ctr_stream(&key, &nonce, blocks as usize);
		xor(&pt[..], &keystream)
	}).collect();
	// sort them
	ciphertexts.sort_by(|c1, c2| c1.len().cmp(&c2.len()));

	// start by looking for case switches
	// grab the first ciphertext
	for k in 0..ciphertexts.len() {
		let c1 = ciphertexts[k].clone();
		let mut dec :Vec<Vec<char>> = vec![Vec::new(); c1.len()];
		for (i, c) in ciphertexts.iter().enumerate() {
			if k == i { continue }
			let outp = xor(&c1, c);
			let mut candidates : Vec<(usize, char)> = Vec::new();
			for (j, &b) in outp.iter().enumerate() {
				if (b > 64u8 && b < 91u8) || (b > 96u8 && b < 123u8) {
					candidates.push( (j, b as char) );
					dec[j].push( (b ^ 32) as char);
				}
			}
		}
/*
		// print out possibilities
		// this was useful for getting started
		for (i, v) in dec.iter_mut().enumerate() {
			v.sort();
			v.dedup();
			println!("{:2}: {:?}", i, v);
		}
*/
	} 
	// ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'm', 'n', 'o', 'r', 's', 't', 'v']
	let mut key_cand = xor(b"Transformed ", &ciphertexts[0]); 
	key_cand.append(&mut xor(b"companion", &ciphertexts[1][12..]));
	key_cand.append(&mut xor(b"t", &ciphertexts[5][21..]));
	key_cand.append(&mut xor(b"d", &ciphertexts[7][22..]));
	key_cand.append(&mut xor(b"l", &ciphertexts[8][23..]));
	key_cand.append(&mut xor(b"rds", &ciphertexts[16][24..]));
	key_cand.append(&mut xor(b"rt", &ciphertexts[27][27..]));
	key_cand.append(&mut xor(b"d", &ciphertexts[33][29..]));
	key_cand.append(&mut xor(b"nd", &ciphertexts[35][30..]));
	key_cand.append(&mut xor(b"d", &ciphertexts[37][32..]));
	key_cand.append(&mut xor(b"ead", &ciphertexts[38][33..]));
	key_cand.append(&mut xor(b"n,", &ciphertexts[39][36..]));

	// ---------------------------------------------------------------------
	// NOTE: the last character was guessed thanks to the code below
	//       I was just curious whether or not i got it dead on.
	//       I suspected it was a punctuation mark, so I guessed until it
	//       was right.
	// ---------------------------------------------------------------------
	let mut count = 0;
	let keystream = ctr_stream(&key, &nonce, ciphertexts[39].len()/16 + 1);
	for (rec, og) in key_cand.iter().zip(keystream.iter()) {
		if og != rec { count += 1 }
	}
	println!("there are {} different bytes", count);
	// ---------------------------------------------------------------------

	/*
	let first = b"Transformed iutter  ";
	let c2 = &ciphertexts[2];
	let thirteenth = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'm', 'n', 'o', 'r', 's', 't', 'v', ' '];
	for &c in thirteenth.iter() {
		if ((c as u8) ^ c2[12] ) as char == 'l' {
			println!("jackpot! : {}", c);
		}
	}

	let mut keystart = xor(&first[..], &c1);
	*/
	for (i, c) in ciphertexts.iter().enumerate() {
		let dec = xor(&key_cand, c);
		println!("{:2}. ({}/{}) {:?}", i, dec.len(), c.len(), String::from_utf8(dec));
	}
}
