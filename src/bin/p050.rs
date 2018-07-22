extern crate ooga;
use ooga::byte_utils::ToHexString;
use ooga::cipher_utils::{cbc_mac, cbc_decrypt_bare};


fn main() {
	let msg = b"alert('MZA who was that?');\n";
	let key = b"YELLOW SUBMARINE";
	let iv = [0u8; 16];

	let mac = cbc_mac(&key[..], &iv[..], &msg[..]);


	println!("original mac: {}", mac.to_hex_string());

	// forge our mac!
	//                      0123456789abcdef0123456789abcdef
	let mut replacement = b"alert('Ayo, the Wu is back!');//".to_vec();
	let pre_mac = cbc_mac(&key[..], &iv[..], &replacement);

	// get a final block to slap on the end
	let mut last_block = cbc_decrypt_bare(&key[..], &pre_mac[..], &mac[..]);

	replacement.append(&mut last_block);
	let printable = replacement.iter().map(|&x| x as char).collect::<String>();
	println!("replacement: {:?}", printable);

	// now verify we have successfully fooled the people!
	let forged_mac = cbc_mac(&key[..], &iv[..], &replacement);

	println!("forged mac: {}", forged_mac.to_hex_string());
}
