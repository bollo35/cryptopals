use std::collections::HashMap;

const INTO_64 : [char; 64]  = [
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
      'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
      'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
      'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
];

lazy_static! {
	static ref OUT_OF_64 : HashMap<char, u32> = {
		let mut m = HashMap::new();
		for (i, c) in INTO_64.iter().enumerate() {
			m.insert(*c, i as u32);
		}
		m
	};
}

pub fn encode(bytes: &[u8]) -> String {
    let extra_bytes = bytes.len() % 3;
    // collect triples
    let mut triples : Vec<u32> = bytes.chunks(3).map(|bytes| 
                                    bytes.iter().fold(0u32, |acc, byte| (acc << 8) | (*byte as u32))
                                    << ((3-bytes.len())*8) ).collect();
    // now split the triples and collect the corresponding 64bit 'digit' into a string
    let last = if extra_bytes > 0 { triples.pop() } else { None };
    let mut encoding = String::with_capacity(triples.len());
    for triple in triples {
        for x in 0..4 {
            let index = (triple >> (6*(4-x-1))) & 0x3F;
            encoding.push(INTO_64[index as usize]);
        }
    }
    if let Some(last) = last {
        let chars = extra_bytes + 1;
        for x in 0..chars {
            let index = (last >> (6 * (4-1-x))) & 0x3F;
            encoding.push(INTO_64[index as usize]);
        }
        // now to add the pad
        // if there's 1 extra byte, then we get 2 '='
        // if there's 2 extra bytes, then we get 1 '='
        for _x in 0..(4 - chars) {
            encoding.push('=');            
        }
    }
    encoding
}

pub fn decode(s: &str) -> Vec<u8> {
    // count the number of '='
    let mut num_eqs = 0;
    let mut x = s.chars().rev();
    while let Some('=') = x.next() {
        num_eqs += 1;
    }
    // iterate in chunks of 4
    let triples : Vec<u32> = s.as_bytes().chunks(4).map( |quad|
                    quad.iter().fold(0u32, |acc, _6bits| {
                        if *_6bits as char == '=' {
                            acc << 6
                        } else {
                            let tmp = *_6bits as char;
                            match OUT_OF_64.get(&tmp) {
                                Some(number) => ( ( acc << 6 ) | number ),
                                None => panic!(format!("Unexpected character {} {:x}", tmp, _6bits)),
                            }
                        }
                    })).collect();
    let mut bytes: Vec<u8> = Vec::with_capacity((s.len()/4)*3);
    // take our 24 bits and convert them to bytes
    for triple in triples {
        for x in 0..3 {
            let byte = (triple >> ((2-x) * 8)) & 0xFF;
            bytes.push(byte as u8);
        }
    }
    
    while num_eqs > 0 {
        bytes.pop();
        num_eqs -= 1;
    }
    
    bytes
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn non_padded_string() {
		let m = b"Hello World!";
		let enc = encode(m);
		assert_eq!(enc[..], "SGVsbG8gV29ybGQh"[..]);

		let dec = decode(&enc);
		assert_eq!(dec[..], m[..]);
	}

	#[test]
	fn padded_strings() {
		// should have 2 
		let m = b"Hell";
		let enc = encode(m);
		assert_eq!(enc[..], "SGVsbA=="[..]);

		let dec = decode(&enc);
		assert_eq!(m[..], dec[..]);

		let m = b"Hello";
		let enc = encode(m);
		assert_eq!(enc[..], "SGVsbG8="[..]);
		let dec = decode(&enc);
		assert_eq!(m[..], dec[..]);
	}
}
