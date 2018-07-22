extern crate ooga;
use ooga::base64;
use ooga::cipher_utils::ctr_stream;
use ooga::byte_utils::xor;

extern crate flate2;

extern crate openssl;
use openssl::symm::{Cipher, Mode, Crypter, encrypt};

extern crate rand;
use rand::Rng;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use std::io::Write;

fn format_request(request: Vec<u8>) -> Vec<u8> {
	let mut prefix = br#"POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: "#.to_vec();

	let content_len = request.len().to_string();
	prefix.append(&mut content_len.into_bytes());
	prefix.push(b'\n');
	prefix.append(&mut request.clone());
	prefix
}


fn oracle(request: Vec<u8>) -> usize {
	// (1) compress
	let compressed_bytes = simple_compress(format_request(request));

	// (2) encrypt
	let nonce = rand::thread_rng().gen_iter::<u8>().take(8).collect::<Vec<u8>>();
	const KEY : &'static [u8; 16] = b"YELLOW SUBMARINE";
	const BLOCK_SIZE : usize = 16;
	let blocks = (compressed_bytes.len() + BLOCK_SIZE - 1) / BLOCK_SIZE;
	let stream = ctr_stream(&KEY[..], &nonce, blocks);
	let encryption = xor(&compressed_bytes, &stream);

	// (3) return the length
	encryption.len()
}

fn cbc_oracle(request: Vec<u8>) -> usize {
	// (1) compress
	let compressed_bytes = simple_compress(format_request(request));

	// (2) Encrypt
	let cipher = Cipher::aes_128_cbc();
	const KEY : &'static [u8; 16] = b"YELLOW SUBMARINE";
	let iv = rand::thread_rng().gen_iter::<u8>().take(16).collect::<Vec<u8>>();
	let encryption = encrypt(cipher,
	                         &KEY[..],
	                         Some(&iv),
	                         &compressed_bytes).unwrap();

	// (3) return the length
	encryption.len()
}

fn simple_compress(stuff: Vec<u8>) -> Vec<u8> {
	let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
	e.write_all(&stuff[..]).unwrap();
	e.finish().unwrap()
}

fn build_request(token: &[u8]) -> Vec<u8> {
	let mut request = br#"POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid="#.to_vec();
	request.extend_from_slice(token);

	request
}

fn main() {
	cbc_recovery();
	stream_cipher_recovery();
}

// SOLUTIONS
fn stream_cipher_recovery() {
	// iterate over each position in the token
	// (1) at each position, determine the letter that compresses to the smallest value
	// (2) if there are multiple matches, then wrap them into the next round and 
	//     try each combination taking the one that compresses to the smallest value
	
	// we know that the sessionId is base64 encoded and is 44 bytes long
	let choices = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	const token_len : usize = 44;
	let mut candidates : Vec<Vec<u8>> = Vec::new();
	candidates.push(Vec::new());
	for i in 0..token_len {
		let mut allcombinations : Vec<(Vec<u8>, usize)> = candidates.iter()
		                                .fold(Vec::with_capacity(65 * candidates.len() + 1), |mut acc, candidate| {
			for c in choices.iter() {
				let mut sessionid = candidate.clone();
				sessionid.push(*c);
				let request = build_request(&sessionid);
				let compression_len = oracle(request);
				acc.push( ( sessionid, compression_len ) )
			}
			acc
		});

		allcombinations.sort_by(|a, b| a.1.cmp(&b.1));

		let min = allcombinations[0].1;
		candidates = allcombinations.iter().take_while(|&x| x.1 == min).map(|x| x.0.clone()).collect::<Vec<Vec<u8>>>();
	}
	
	println!();
	println!();
	println!("--------- S T R E A M  C I P H E R ------------");
	for candidate in candidates.iter() {
		let cookie_str = String::from_utf8(candidate.to_vec()).unwrap();
		println!("candidate = {}", cookie_str);
		let cookie = base64::decode(&cookie_str);
		println!("cookie = {:?}", String::from_utf8(cookie).unwrap());

	}
	println!("-----------------------------------------------");
}

fn cbc_recovery() {
	// fish for block size boundary
	// (1) get empty compression size
	let base_len = cbc_oracle(Vec::new());

	// (2) generate a block of random bytes, and figure out how many are
	//     to make the encryption require an extra block
	let random_bytes = rand::thread_rng().gen_iter::<u8>().take(44).collect::<Vec<u8>>();
	let mut bytes_needed = 1;
	while base_len == cbc_oracle(build_request(&random_bytes[..bytes_needed])) {
		bytes_needed += 1;
	}

	
	// iterate over each position in the token
	// (1) at each position, determine the letter that compresses to the smallest value
	// (2) if there are multiple matches, then wrap them into the next round and 
	//     try each combination taking the one that compresses to the smallest value
	
	// we know that the sessionId is base64 encoded and is 44 bytes long
	let choices = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	const token_len : usize = 44;
	let mut candidates : Vec<Vec<u8>> = Vec::new();
	candidates.push(random_bytes[..bytes_needed].to_vec());
	for i in 0..token_len {
		let mut allcombinations : Vec<(Vec<u8>, usize)> = candidates.iter()
		                                .fold(Vec::with_capacity(65 * candidates.len() + 1), |mut acc, candidate| {
			for c in choices.iter() {
				let mut sessionid = candidate.clone();
				sessionid[i] = *c;
				let request = build_request(&sessionid.clone());
				let compression_len = cbc_oracle(request);
				acc.push( ( sessionid, compression_len ) )
			}
			acc
		});

		allcombinations.sort_by(|a, b| a.1.cmp(&b.1));

		let min = allcombinations[0].1;
		candidates = allcombinations.iter().take_while(|&x| x.1 == min).map(|x| {
			let mut t = x.0.clone();
			t.truncate(i+1);
			t
		}).collect::<Vec<Vec<u8>>>();


		// I could probably rearrange this
		// to avoid breaking, but it's so late that it's early
		// and i just want to see if this works
		if i == token_len - 1 { break; }
		// determine how many random bytes we need to require an extra block
		// we should only have one candidate here, or we're probably screwed
		// maybe not. need to think about this a little bit more
		let mut tmp = candidates[0].clone(); 
		let base_len = cbc_oracle(build_request(&tmp));

		bytes_needed = 0;
		tmp.push(random_bytes[bytes_needed]);
		while base_len == cbc_oracle(build_request(&tmp)) {
			bytes_needed +=1;
			tmp.push(random_bytes[bytes_needed]);
		}

		candidates = candidates.iter().map(|x| {
			let mut t = x.clone();
			t.extend_from_slice(&random_bytes[..(bytes_needed+1)]);
			t
		}).collect::<Vec<Vec<u8>>>();
		
	}
	
	println!();
	println!();
	println!("------------ C B C  C I P H E R ----------------");
	for candidate in candidates.iter() {
		let cookie_str = String::from_utf8(candidate.to_vec()).unwrap();
		println!("candidate = {}", cookie_str);
		let cookie = base64::decode(&cookie_str);
		println!("cookie = {:?}", String::from_utf8(cookie).unwrap());

	}
	println!("-----------------------------------------------");
}
