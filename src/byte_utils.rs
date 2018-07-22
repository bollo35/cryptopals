use std::mem;

pub trait ToByteVector {
	fn to_byte_vec(&self) -> Vec<u8>;
}

impl ToByteVector for str {
	// assumes that the string only contains hex digits
	// will panic if some other character is in the string
	fn to_byte_vec(&self) -> Vec<u8> {
		self.chars().map(|x| x.to_digit(16).unwrap() as u8).collect::<Vec<u8>>().
		     chunks(2).map(|x| x[0] << 4 | x[1]).
		     collect::<Vec<u8>>()
	}
}

impl ToByteVector for [u32] {
	fn to_byte_vec(&self) -> Vec<u8> {
		self.iter().fold(Vec::with_capacity(self.len()*4), |mut acc, &v| {
			let arr = unsafe { mem::transmute::<u32, [u8;4]>( v.to_be() ) };
			acc.extend_from_slice(&arr);
			acc
		})
	}
}

pub trait ToBlockVector {
	fn to_blocks(&self) -> Vec<u128>;
}

impl ToBlockVector for [u8] {
	// we're just going to assume that everything is of the right block size.
	fn to_blocks(&self) -> Vec<u128> {
		self.chunks(16).map(|chunk| chunk.iter().fold(0u128, |acc, &byte| (acc << 8) | (byte as u128))).collect()
	}
}

impl ToBlockVector for Vec<u8> {
	// we're just going to assume that everything is of the right block size.
	fn to_blocks(&self) -> Vec<u128> {
		self.chunks(16).map(|chunk| chunk.iter().fold(0u128, |acc, &byte| (acc << 8) | (byte as u128))).collect()
	}
}

pub trait ToEscapedString {
	fn to_escaped_str(&self) -> String;
}

impl ToEscapedString for [u8] {
	fn to_escaped_str(&self) -> String {
		self.iter().map(|&c| format!("\\x{:02x}",c)).collect::<String>()
	}
}
impl ToHexString for Vec<u8> {
	fn to_hex_string(&self) -> String {
		self.iter().map(|a| format!("{:02x}", a)).collect::<String>()	
	}
}

impl ToHexString for [u32] {
	fn to_hex_string(&self) -> String {
		self.iter().map(|a| format!("{:08x}", a)).collect::<String>()	
	}
}

impl ToHexString for [u8] {
	fn to_hex_string(&self) -> String {
		self.iter().map(|a| format!("{:02x}", a)).collect::<String>()	
	}
}

pub fn repeated_xor_enc(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
	let key_str : Vec<u8> = key.iter().cycle().take(plaintext.len()).map(|&x| x).collect();
	xor(plaintext, &key_str)
}

// Returns the xor of two byte arrays
// truncates based on the shorter of the two arrays
pub fn xor(a1: &[u8], a2: &[u8]) -> Vec<u8> {
	let (a1, a2) = if a1.len() > a2.len() {
	                   (a2, a1)
	               } else { 
	                   (a1, a2)
	               };
	a1.iter().zip(a2.iter()).map(|(a,b)| a ^ b).collect::<Vec<u8>>()
}

pub trait ToHexString {
	fn to_hex_string(&self) -> String;
}

