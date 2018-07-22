const LETTER_FREQS : [f64; 26]= [
	0.08167, // A
	0.01492, // B
	0.02782, // C
	0.04253, // D
	0.12702, // E
	0.02228, // F
	0.02015, // G
	0.06094, // H
	0.06966, // I
	0.00153, // J
	0.00772, // K
	0.04025, // L
	0.02406, // M
	0.06749, // N
	0.07507, // O
	0.01929, // P
	0.00095, // Q
	0.05987, // R
	0.06327, // S
	0.09056, // T
	0.02758, // U
	0.00978, // V
	0.02360, // W
	0.00150, // X
	0.01974, // Y
	0.00074, // Z
];

const FIRST_LETTER_FREQS : [f64; 26]= [
	0.11682, // A
	0.04434, // B
	0.05238, // C
	0.03174, // D
	0.02799, // E
	0.04027, // F
	0.01642, // G
	0.04200, // H
	0.07294, // I
	0.00511, // J
	0.00456, // K
	0.02415, // L
	0.03826, // M
	0.02284, // N
	0.07631, // O
	0.04319, // P
	0.00222, // Q
	0.02826, // R
	0.06686, // S
	0.15978, // T
	0.01183, // U
	0.00824, // V
	0.05497, // W
	0.00045, // X
	0.00763, // Y
	0.00045, // Z
];

fn score_plaintext(chars: &[u8], letter_freqs: &[f64; 26]) -> f64 {
	let num_chars = chars.len();
	let mut freqs = vec![0; 26];

	for &c in chars.iter() {
		if c >= 'A' as u8 && c <= 'Z' as u8 {
			freqs[ c as usize - 'A' as usize] += 1;
		} else if c >= 'a' as u8 && c <= 'z' as u8 {
			freqs[ c as usize - 'a' as usize] += 1;
		}
	}

	let total_score = freqs.iter().enumerate().fold(1.0,|total, (i, &current)| { 
		let f = current as f64/num_chars as f64;
		total * (f - letter_freqs[i]).abs()/letter_freqs[i]
	});

	total_score
}

pub struct ScoredPlainText {
	pub key: u8,
	pub score: f64,
	pub plaintext: String,
}

impl ScoredPlainText {
	fn new (key: u8, score: f64, plaintext: Vec<u8>) -> ScoredPlainText {
		ScoredPlainText { 
			key: key,
			score: score,
			plaintext: String::from_utf8(plaintext).unwrap() // EVIL!!!
		}
	}
}

pub fn rank_1byte_xor(msg: &[u8], first_letter: bool) -> Vec<ScoredPlainText> {
	let mut candidates = Vec::<ScoredPlainText>::new();
	for i in 1..256usize {
		let mut good_guess = true;
		let mut candidate = Vec::<u8>::with_capacity(msg.len());
		for j in msg.iter() {
			let xor = j ^ i as u8;
			if (xor < 32 || xor > 126) && 
			   (xor != b'\r' && xor != b'\n' && xor != b'\t') {
				good_guess = false;
				break;
			} else {
				candidate.push(xor);
			}
		}
		if good_guess {
			let letter_freqs = if first_letter { &FIRST_LETTER_FREQS } else { &LETTER_FREQS };
			let spt = ScoredPlainText::new(i as u8, score_plaintext(&candidate, letter_freqs), candidate);
			candidates.push(spt);
		}
	}
	// sort candidates
	candidates.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
	candidates
}
