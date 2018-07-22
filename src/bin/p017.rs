extern crate ooga;
use ooga::base64;
use ooga::cipher_utils::{cbc_encrypt, cbc_decrypt_bare, pkcs7_remove};
extern crate rand;
use rand::Rng;
use rand::distributions::{Range, Sample};

fn main() {
	// generate a random AES key
	let mut rng = rand::thread_rng();
	let key = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();

	let ct = sel_and_enc(&key);

	let mut recovered_text = Vec::with_capacity(ct.len() - 1);
	let num_blocks = ct.len() / 16;

	for i in 0..num_blocks-1 {
		let mut rec = recover_block(&ct[i*16..(i+2)*16], &key);
		recovered_text.append(&mut rec);
	}

	println!("recovered text: {}", String::from_utf8(pkcs7_remove(&recovered_text).unwrap()).unwrap());
}

/*
 * CBC decryption: P[i] = C[i-1] ^ D(C[i])
 * If we want P[i] to have a specific value,
 *  we can xor it with a guess to try to make
 *  that happen:
 *   g ^ P[i] = value = g ^ C[i-1] ^ D(C[i])
 * Once we have gotten the desired value, we
 *  can recover the original plaintext value:
 *    P[i] = g ^ value
 * When we want to change the padding value
 *  at P[i] for the next character of plaintext:
 *    g' = P[i] ^ pad_len
 *  so since pad_len = g' ^ C[i-1] ^ D(C[i]): 
 *    C'[i-1] = P[i] ^ pad_len ^ C[i-1]
 */
fn recover_block(input: &[u8], key: &[u8]) -> Vec<u8> {
	let mut recovered  = vec![0u8; 16];
	let mut scratch = [0u8; 32];
	scratch[..].clone_from_slice(&input);
	for pad_len in 1..17 {
		let index = 16 - pad_len;
		let mut valid = false;
		let mut dubious = false;
		for guess in 0..256usize {
			scratch[index] = input[index] ^ guess as u8;
			for k in index+1..16 {
				scratch[k] = input[k] ^ recovered[k] ^ pad_len as u8;
			}
			if pad_oracle(&scratch[..], &key) {
				if guess == 0 && pad_len == 1 {
					dubious = true;
				} else {
					recovered[index] = guess as u8 ^ pad_len as u8;
					valid = true;
					break;
				}
			}
		}
		if !valid && dubious { 
			recovered[index] = 1;
		}
	}
	recovered
}

// returns ciphertext in the form [iv][ct]
fn sel_and_enc(key: &[u8]) -> Vec<u8> {
	let mut rng = rand::thread_rng();
	let rand_index = Range::new(0usize, 10).sample(&mut rng);
	const STRINGS: &'static [&'static str] = &[
					 "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="                            ,
					 "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
					 "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="        ,
					 "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="                    ,
					 "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"            ,
					 "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="                        ,
					 "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="                ,
					 "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="                    ,
					 "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="                                ,
					 "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"                ,
					];
	let iv = rng.gen_iter::<u8>().take(16).collect::<Vec<u8>>();
	let mut final_ct = iv.clone();
	let pt = base64::decode(STRINGS[rand_index]);
	final_ct.append(&mut cbc_encrypt(key, &iv, &pt));
	final_ct
}

fn pad_oracle(input: &[u8], key: &[u8]) -> bool {
	let iv = &input[0..16];
	let dec = cbc_decrypt_bare(key, &iv, &input[16..]);
	let res = pkcs7_remove(&dec);//[start..]);
	res.is_ok()
}
