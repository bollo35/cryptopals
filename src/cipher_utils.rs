use openssl::symm::{Cipher, Mode, Crypter, encrypt, decrypt};

use byte_utils::{xor, ToBlockVector};

// -----------------------[PKCS 7]-------------------------
pub fn pkcs7_padding(mut block: Vec<u8>, block_len: usize) -> Vec<u8> {
	if block.len() > block_len {
		panic!(format!("Expected block size of {} bytes, but provided block has size of {} bytes", block_len, block.len()));
	} else if block.len() == block_len {
		// add a full block
		let mut new_block = (0..block_len).map(|_| block_len as u8).collect::<Vec<u8>>();
		block.append(&mut new_block);
	} else {
		let pad : u8 = (block_len - block.len()) as u8;
		for _i in 0..pad {
			block.push(pad);
		}
	}
	block
}

pub fn pkcs7_remove(block: &[u8]) -> Result<Vec<u8>, &'static str> {
	if let Some(&to_rem) = block.last() {

		if block.len() < to_rem as usize || to_rem == 0 { return Err("Invalid Padding!"); }

		let start_index = block.len() - to_rem as usize;
		for &ch in block[start_index..].iter() {
			if ch != to_rem {
				return Err("Invalid Padding!");
			}
		}
		Ok(block[..start_index].to_vec())
	} else {
		Err("Invalid Padding!")
	}
}

// -----------------------[CBC FUNCTIONS]-----------------------------
pub fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
	let cipher = Cipher::aes_128_ecb();
	let mut encrypter = Crypter::new(
		cipher,
		Mode::Encrypt,
		key,
		None).unwrap();
	let mut output = vec![0; data.len() + 2*cipher.block_size()];

	let block_len = cipher.block_size();

	let mut count = 0;
	let mut last_ct = iv.to_vec();
	let mut block_start = 0;
	let num_blocks = data.len() / block_len + if data.len() % block_len == 0 {0} else {1};

	for (i,block) in data.chunks(block_len).enumerate() {

		let last_block = i == num_blocks - 1;
		// if this is the last block
		let blk = 
			if last_block {
				pkcs7_padding(block.to_vec(), block_len)
			} else {
				block.to_vec()
			};
		// xor the plaintext with the IV or the last block of ciphertext
		let mut xored = xor(&last_ct, &blk);

		// encrypt the result
		count += encrypter.update(&xored, &mut output[count..]).unwrap();
		last_ct.clear();
		for x in &output[block_start..block_start+block_len] {
			last_ct.push(*x);
		}

		// add a padding of block_len if necessary
		if last_block && blk.len() > block_len {
			let mut xored = xor(&last_ct, &blk[block_len..]);
			count += encrypter.update(&xored, &mut output[count..]).unwrap();
		}
		block_start += block_len;
	}
	output.truncate(count);
	output
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
	let dec = cbc_decrypt_bare(key, iv, ciphertext);
	pkcs7_remove(&dec)
}

pub fn cbc_decrypt_bare(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
	let cipher = Cipher::aes_128_ecb();

	let dumb_pt = vec![0; key.len()];
	let mut temp_ct = encrypt(cipher, key, None, &dumb_pt).unwrap();
	let mut output = Vec::with_capacity(ciphertext.len());
	let block_len = cipher.block_size();

	let mut last_ct = iv.to_vec();
	let num_blocks = (ciphertext.len() / block_len) + if ciphertext.len() % block_len == 0 {0} else {1};
	let mut block_num = 0;

	while block_num != num_blocks {
		// decrypt the current block
		// add block to our temporary thing
		let block_start = block_num * block_len;
		for i in 0..block_len {
			temp_ct[i] = ciphertext[block_start + i];
		}

		let dec = decrypt(
					cipher,
					key,
					None,
					&temp_ct[..]).unwrap();

		let mut pt = xor(&last_ct, &dec);
		for i in 0..block_len {
			last_ct[i] = temp_ct[i];
		}
		output.append(&mut pt);
		block_num += 1;
	}
	output
}

pub fn cbc_mac(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
	let cipher = Cipher::aes_128_ecb();
	let mut encrypter = Crypter::new(
		cipher,
		Mode::Encrypt,
		key,
		None).unwrap();
	let mut output = vec![0; data.len() + 2*cipher.block_size()];

	let block_len = cipher.block_size();

	let mut count = 0;
	let mut last_ct = iv.to_vec();
	let mut block_start = 0;
	let num_blocks = data.len() / block_len + if data.len() % block_len == 0 {0} else {1};

	for (i,block) in data.chunks(block_len).enumerate() {
		// if this is the last block
		// xor the plaintext with the IV or the last block of ciphertext
		let mut xored = xor(&last_ct, &block);

		// encrypt the result
		count += encrypter.update(&xored, &mut output[count..]).unwrap();
		last_ct.clear();
		for x in &output[block_start..block_start+block_len] {
			last_ct.push(*x);
		}
		block_start += block_len;
	}

	output.truncate(count);
	let start = count - block_len;
	output[start..].to_vec()
}

// -----------------------[ECB FUNCTIONS]-----------------------------
pub fn ecb_encrypt(key: &[u8], iv: Option<&[u8]>, plaintext: &[u8]) -> Vec<u8> {
	encrypt (
	    Cipher::aes_128_ecb(),
	    &key,
	    iv,
	    &plaintext[..]).unwrap()
}

pub fn ecb_decrypt(key: &[u8], iv: Option<&[u8]>, ciphertext: &[u8]) -> Vec<u8> {
	decrypt (
	    Cipher::aes_128_ecb(),
	    &key,
	    iv,
	    &ciphertext[..]).unwrap()
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionScheme {
	CBC,
	ECB,
}

pub fn detect_encryption_scheme(encryption: &[u8]) -> EncryptionScheme {
	let mut blocks = encryption.to_blocks();
	let initial_len = blocks.len();
	blocks.dedup();
	if blocks.len() == initial_len {
		EncryptionScheme::CBC
	} else {
		EncryptionScheme::ECB
	}
}

// ------------------[CTR STREAM]--------------------
pub fn ctr_stream(key: &[u8], nonce: &[u8], blocks: usize) -> Vec<u8> {
	let cipher = Cipher::aes_128_ecb();
	let mut encrypter = Crypter::new(
		cipher,
		Mode::Encrypt,
		key,
		None).unwrap();

	let mut output = vec![0u8; blocks * 3 *cipher.block_size()];
	let mut counter : u64 = 0;
	let increment = 1;
	let mut count = 0;
	let mut block = [0u8; 16];

	block[0..8].copy_from_slice(nonce);
	
	for _ in 0..blocks {
		// update the block with the new counter
		for j in 0..8 {
			block[8+j] = (counter >> (8*j)) as u8 & 0xFFu8;
		}
		count += encrypter.update(&block, &mut output[count..]).unwrap();
		counter += increment;
	}
	output.truncate(count);
	output
}
#[cfg(test)]
mod test {
	use super::*;
	#[test]
	fn cbc_mode_test() {
		let key = b"YELLOW SUBMARINE";
		let iv = vec![0u8; 16];
		let pt = b"I saw a ship o'er yonder. There be pirates there, doing the things that them pirates be doing.";
		let enc = cbc_encrypt(&key[..], &iv[..], &pt[..]);

		let dec = cbc_decrypt(&key[..], &iv[..], &enc[..]);

		assert_eq!(pt[..], dec[..]);
	}

	#[test]
	fn pkcs7_tests() {
		let block_len = 16;
		let block = vec![0u8; 16];
		
		let mut expected = vec![0u8; 16];
		expected.append(&mut vec![16u8; 16]);

		let full_block_with_pad = pkcs7_padding(block, block_len);
		assert_eq!(expected[..], full_block_with_pad[..]);

		let block = vec![0u8; 8];
		let mut expected = vec![0u8; 8];
		expected.append(&mut vec![8u8; 8]);
		
		let padded_block = pkcs7_padding(block, block_len);
		assert_eq!(expected[..], padded_block[..]);
	}
}

