extern crate ooga;
use ooga::md4::{md4, md4_attack};
use ooga::byte_utils::{ToHexString, ToEscapedString};

extern crate rand;
use rand::Rng;
use rand::distributions::{Sample, Range};

use std::mem;

fn main() {
	let mut rng = rand::thread_rng();
	// determine a random number of bytes to choose
	let mut between = Range::new(32usize, 128);
	let num_bytes = between.sample(&mut rng);
	// generate a random prefix key
	let key = rng.gen_iter::<u8>().take(num_bytes).collect::<Vec<u8>>();
	let key_clone = key.clone();
	let generate_mac = move |input: &[u8]| -> [u32; 4] {
		let mut msg = Vec::with_capacity(key.len() + input.len());
		msg.extend_from_slice(&key);
		msg.extend_from_slice(input);
		md4(msg)
	};
	
	let addition = b";admin=true";

	// =================================================================
	// GENERATE H(k||m)
	let message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec();
	let hash = generate_mac(&message);
	// swap the byte order for pushing back through when attempting to forge
	let hash = [hash[0].to_be(), hash[1].to_be(), hash[2].to_be(), hash[3].to_be()];
	// =================================================================

	// GENERATE H( k || m || padding || ';admin=true')
	let mut tmp = Vec::with_capacity(key_clone.len() + message.len());
	tmp.extend_from_slice(&key_clone);
	tmp.extend_from_slice(&message);
	let mut forged_msg = padded_msg(&tmp, 0);
	forged_msg.extend_from_slice(&addition[..]);

	let expected_hash = md4(forged_msg);
	println!("EXPECTED HASH: {}", expected_hash.to_hex_string());

	// take an initial swipe at determining the key length
	let mut key_len = 0;
	let mut semi_forged = false;
	while !semi_forged {
		key_len += 1;
		let padded_msg_len = padded_len(message.len(), key_len);
		let extended_hash = md4_attack(addition.to_vec(), hash, padded_msg_len);
		semi_forged = extended_hash == expected_hash;
	}

	// we need to determine the actual key size now
	let mut forged_message;
	loop {
		forged_message = padded_msg(&message[..], key_len);
		forged_message.extend_from_slice(&addition[..]);
		if generate_mac(&forged_message) == expected_hash {
			break;
		} else if key_len > 128 {
			println!("FAAIIIIIIIIIIIIIIIIIL");
			break;
		} else {
			key_len += 1;
		}
	}

	let pad_start = message.len();
	let pad_end = forged_message.len() - addition.len();
	println!("-----------------------------------");
	print!("msg: {}", String::from_utf8(message).unwrap());
	print!("{}", forged_message[pad_start..pad_end].to_escaped_str());
	println!("{}",String::from_utf8(addition.to_vec()).unwrap());
	println!("-----------------------------------");

	let final_hash = generate_mac(&forged_message);
	println!("final hash: {}", final_hash.to_hex_string());
	println!("final hash == expected hash? {}", final_hash == expected_hash);
}

fn padded_len(msg_len: usize, additional_len: usize) -> usize {
	let l = (msg_len + additional_len) * 8;
	let k = 448usize.wrapping_sub(l % 512).wrapping_sub(8) % 512;
	let bytes = k / 8 + if k % 8 > 0 { 1 } else { 0 } + 1; // the extra 1 is for the 0x80 that gets appended
	msg_len + additional_len + bytes + 8 /* 8 bytes for the 64bit length */
}

fn padded_msg(msg: &[u8], byte_len: usize) -> Vec<u8> {
	let mut mclone = msg.clone().to_vec();

	let l = (mclone.len() + byte_len) * 8;
	mclone.push(0x80);

	let k = 448usize.wrapping_sub(l % 512).wrapping_sub(8) % 512;
	let bytes = k / 8 + if k % 8 > 0 { 1 } else { 0 };

	mclone.append(&mut vec![0; bytes]);
	let len64b = unsafe { mem::transmute::<u64, [u8; 8]>( (l as u64).to_le() ) };
	mclone.extend_from_slice(&len64b[..]);

	mclone
}
