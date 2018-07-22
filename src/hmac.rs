extern crate openssl;
use openssl::sha::sha256;

use byte_utils::xor;

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
	let block_size = 64usize;
	let mut hkey = if key.len() > block_size {
		sha256(key)[..].to_vec()
	} else {
		key.clone().to_vec()
	};

	while hkey.len() < block_size {
		hkey.push(0u8);
	}

	let mut okey = xor(&hkey, &vec![0x5c; block_size]); 
	let mut ikey = xor(&hkey, &vec![0x36; block_size]); 

	ikey.extend_from_slice(msg);
	let mut ihash = sha256(&ikey[..])[..].to_vec();
	okey.append(&mut ihash);
	sha256(&okey[..]).iter().map(|x| format!("{:02x}", x)).collect::<String>()
}
