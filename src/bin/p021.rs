// http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/MT2002/CODES/mt19937ar.c
pub struct MT19937 {
	shr: Vec<u32>,
	i: usize,
}

const N : usize = 624;
const W : u32 = 32;
const M : usize = 397;
const UPPER_MASK : u32 = 0x80000000u32;
const LOWER_MASK : u32 = 0x7FFFFFFFu32;
const MATRIX : [u32; 2] = [ 0u32, 0x9908b0dfu32 ];
impl MT19937 {
	pub fn new(seed: u32) -> MT19937 {
		let mut rng = MT19937 {
			shr: Vec::with_capacity(N),
			i: 0,
		};
		rng.init(seed);
		rng
	}

	fn init(&mut self, seed: u32) {
		let f = 1812433253u32;
		self.shr = Vec::with_capacity(N);
		self.shr.push(seed);

		let f = 1812433253u64;
		let mut xi_1 = seed;
		for i in 1..N {
			let next = f * ( (xi_1 ^ (xi_1 >> (W-2))) as u64 ) + i as u64;
			self.shr.push( (next & 0x00000000FFFFFFFF) as u32 );
			xi_1 = *self.shr.last().unwrap();
		}
		self.i = N;
	}

	pub fn next(&mut self) -> u32 {
		let mut y;
		if self.i >= N {
			for kk in 0..N-M {
				y = (self.shr[kk] & UPPER_MASK) | (self.shr[kk+1] & LOWER_MASK);
				self.shr[kk] = self.shr[kk + M] ^ (y >> 1) ^ MATRIX [ (y & 0x01) as usize ];
			}

			for kk in (N-M)..N-1 {
				y = (self.shr[kk] & UPPER_MASK) | (self.shr[kk+1] & LOWER_MASK);
				self.shr[kk] = self.shr[kk + M - N] ^ (y >> 1) ^ MATRIX [ (y & 0x01) as usize ];
			}
			y = (self.shr[N-1] & UPPER_MASK) | (self.shr[0] & LOWER_MASK);
			self.shr[N-1] = self.shr[M-1] ^ (y >> 1) ^ MATRIX [ (y & 0x01) as usize ];

			self.i = 0;
		}

		y = self.shr[self.i];
		self.i += 1;

		y ^= y >> 11;
		y ^= (y << 7) & 0x9d2c5680;
		y ^= (y << 15) & 0xefc60000;
		y ^= y >> 18;

		y
	}
}

fn main() {
	let mut rng = MT19937::new(1521856540);
	for i in 0..15 {
		println!("{:2}. {}", i, rng.next());
	}
}
