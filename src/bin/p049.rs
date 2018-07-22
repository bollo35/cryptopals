extern crate ooga;
use ooga::byte_utils::{ToHexString, xor};
use ooga::cipher_utils::cbc_mac;

extern crate rand;
use rand::Rng;
use rand::distributions::{Uniform};

use std::collections::HashMap;

// we'll be lame and configure it this way to make it easier
// to execute the attack
const NUM_ACCOUNTS : u32 = 10;
const ACCOUNT_ID_START : u32 = 10;

fn ascii_to_num(ascii: u8) -> Option<u8> {
	if ascii.is_ascii_digit() {
		Some(ascii - b'0')
	} else if ascii.is_ascii_hexdigit() && ascii.is_ascii_uppercase() {
		Some(ascii - b'A' + 10)
	} else if ascii.is_ascii_hexdigit() && ascii.is_ascii_lowercase() {
		Some(ascii - b'a' + 10)
	} else {
		None
	}
}

fn byte_str_to_bytes(byte_str: &[u8]) -> Vec<u8> {
	byte_str.chunks(2).map(|x| ascii_to_num(x[0]).unwrap() << 4 | ascii_to_num(x[1]).unwrap())
	        .collect::<Vec<u8>>()
}

#[derive(Copy, Clone)]
struct Transaction {
	to: u32,
	amount: u32,
}

impl Transaction {
	fn new(to: u32, amount: u32) -> Transaction {
		Transaction {
			to: to,
			amount: amount,
		}
	}
}

#[derive(PartialEq, Eq, Copy, Clone)]
struct Account {
	funds: u32,
	id: u32,
}

impl Account {
	fn new(id: u32, funds: u32) -> Account {
		Account { funds: funds, id: id }
	}
}

struct Client {
	id: u32,
	key: Vec<u8>,
}

impl Client {
	fn new(id: u32, key: &[u8]) -> Client {
		Client {
			id: id,
			key: key.to_vec(),
		}
	}

	fn id(&self) -> u32 {
		self.id
	}

	fn transfer_request(&self, tx_list: Vec<Transaction>) -> Vec<u8> {
		let txns = tx_list.iter().map(|x| format!("{}:{}", x.to, x.amount)).collect::<Vec<String>>().join(";");
		let mut request = format!("from={}&tx_list={}", self.id, txns);
		let mac = cbc_mac(&self.key, &vec![0u8; 16], request.as_bytes());
		format!("{}{}", request, mac.to_hex_string()).as_bytes().to_vec()
	}

	fn transfer_request_iv(&self, to: u32, amount: u32) -> Vec<u8> {
		let range = Uniform::new_inclusive(0, 255u8);
		let iv = rand::thread_rng().sample_iter(&range).take(16).collect::<Vec<u8>>();
		self.format_request_iv(to, amount, &iv)
	}

	fn format_request_iv(&self, to_id: u32, amount: u32, iv: &[u8]) -> Vec<u8> {
		let request = format!("from={}&to={}&amount={}", self.id, to_id, amount);
		let mac = cbc_mac(&self.key, &iv, request.as_bytes());
		format!("{}{}{}", request, iv.to_hex_string(), mac.to_hex_string()).as_bytes().to_vec()
	}
}

struct Server {
	key: Vec<u8>,
	accounts: HashMap<u32, Account>,
}

impl Server {
	fn new() -> Server {
		// generate some new accounts
		// all high rollers
		let range = Uniform::new_inclusive(3_000_000u32, 0xFFFF_FFFFu32);
		let mut accounts = HashMap::new();

		for (funds, id) in rand::thread_rng().sample_iter(&range).take(NUM_ACCOUNTS as usize).zip(ACCOUNT_ID_START..(ACCOUNT_ID_START+NUM_ACCOUNTS)) {
			accounts.insert(id, Account::new(id, funds));
		}

		let range = Uniform::new_inclusive(0, 255u8);
		let key = rand::thread_rng().sample_iter(&range).take(16).collect::<Vec<u8>>();

		Server {
			key: key,
			accounts: accounts,
		}
	}

	fn new_client(&self) -> Client {
		let id = rand::thread_rng().sample(Uniform::new_inclusive(ACCOUNT_ID_START, ACCOUNT_ID_START + NUM_ACCOUNTS - 1));
		Client::new(id, &self.key)
	}

	fn new_client_with_id(&self, id: u32) -> Client {
		Client::new(id, &self.key)
	}

	fn process_request(&mut self, request: Vec<u8>) -> String {
		let mac_start = request.len() - 16*2;
		let request_mac = byte_str_to_bytes(&request[mac_start..]);
		let request_url = request[..mac_start].to_vec();

		let mac = cbc_mac(&self.key, &vec![0u8; 16], &request_url);
		
		// verify transaction mac
		if mac != request_mac {
			return "Invalid transaction".to_string();
		}

		if request_url[..5] != b"from="[..] {
			return "Invalid transaction: couldn't locate from account".to_string();
		}

		let mut index = 5;
		let mut tmp = String::with_capacity(20); // arbitrary
		while request_url[index] != b'&' {
			tmp.push(request_url[index] as char);
			index += 1;
		}

		let from_id = tmp.parse::<u32>().unwrap();
		tmp.clear();

		if !self.accounts.contains_key(&from_id) {
			return "Invalid transaction: Account not found.".to_string();
		}


		if request_url[index..(index + 9)] != b"&tx_list="[..] {
			return "Invalid transaction: Could not locate transaction list.".to_string();
		}

		index += 9;
		let mut transactions = Vec::with_capacity(10);
		let mut total_deduction = 0;
		loop {
			// (1) consume until we find a ':'
			while index < request_url.len() && request_url[index] != b':' {
				tmp.push(request_url[index] as char);
				index += 1;
			}
			// (2) try to convert to a number (to id)
			let to = tmp.parse::<u32>().unwrap();
			tmp.clear();

			// abort if 'to' id doesn't exist
			if !self.accounts.contains_key(&to) {
				return "Invalid transaction: Account not found.".to_string();
			}

			// (3) skip the ':'
			index += 1;

			// (4) consume until end of request or ';'
			while index < request_url.len() && request_url[index] != b';' {
				tmp.push(request_url[index] as char);
				index += 1;
			}
			let amount = tmp.parse::<u32>().unwrap();
			total_deduction += amount;
			tmp.clear();
			transactions.push(Transaction::new(to, amount));

			// (4a) if end of request, then break
			if index == request_url.len() { 
				break;
			}

			// (4b) skip the ';'
			index += 1;
		}

		// process transactions...
		{
			let from_account = self.accounts.get_mut(&from_id).unwrap();
			if from_account.funds < total_deduction {
				return format!("Invalid transaction: Account does not contain {} spacebucks.", total_deduction);
			}

			from_account.funds -= total_deduction;
		}

		for txn in transactions {
			let recipient = self.accounts.get_mut(&txn.to).unwrap();
			recipient.funds += txn.amount;	
		}

		"Transactions successful!".to_string()
	}

	// Looking back at this, I should have just converted the request to a string
	// to do the processing...
	fn process_iv_request(&mut self, request: Vec<u8>) -> String {
		// how to do this?
		assert!(request.len() >  48); // IV + MAC + from/to/amount

		let mac_start = request.len() - 16*2;
		let iv_start  = request.len() - 32*2;
		let request_mac = byte_str_to_bytes(&request[mac_start..]);
		let request_iv = byte_str_to_bytes(&request[iv_start..mac_start]);

		let request_url = request[..iv_start].to_vec();

		let mac = cbc_mac(&self.key, &request_iv, &request_url);

		// verify transaction mac
		if mac != request_mac {
			return "Invalid transaction".to_string();
		}

		if request_url[..5] != b"from="[..] {
			return "Invalid transaction: couldn't locate from account".to_string();
		}
		// now keep going until we hit an ampersand
		let mut index = 5;
		let mut tmp = String::with_capacity(request.len() - 48);
		while request_url[index] != b'&' {
			tmp.push(request_url[index] as char);
			index += 1;
		}

		let from_id = tmp.parse::<u32>().unwrap();
		tmp.clear();

		if request_url[index..(index+4)] != b"&to="[..] {
			return "Invalid transaction: couldn't locate to account".to_string();
		}
		index += 4;
		while request_url[index] != b'&' {
			tmp.push(request_url[index] as char);
			index += 1;
		}

		let to_id = tmp.parse::<u32>().unwrap();

		if request_url[index..(index+8)] != b"&amount="[..] {
			return "Invalid transaction: couldn't locate amount to transfer".to_string();
		}
		index += 8;
		tmp.clear();
		for c in request_url[index..].iter() {
			tmp.push(*c as char);
			index += 1;
		}

		let xfer_amount = tmp.parse::<u32>().unwrap();
		// are the accounts valid?
		if !self.accounts.contains_key(&from_id) || !self.accounts.contains_key(&to_id) {
			return "Invalid account number".to_string();
		}

		{
			let from_account = self.accounts.get_mut(&from_id).unwrap();
			if from_account.funds < xfer_amount {
				return format!("Invalid transaction: Account does not contain {} spacebucks.", xfer_amount);
			}

			from_account.funds -= xfer_amount;
		}

		let to_account = self.accounts.get_mut(&to_id).unwrap();
		to_account.funds += xfer_amount;
		format!("Successfully transfered {} spacebucks from account# {} to account# {}", xfer_amount, from_id, to_id)
	}
}

fn main() {

	// PART 1
	let mut server = Server::new();
	let client = server.new_client();
	let target = (client.id() + 5) % NUM_ACCOUNTS + ACCOUNT_ID_START;
	let my_account2 = (client.id() + 2) % NUM_ACCOUNTS + ACCOUNT_ID_START;
	let mut pre_iv = format!("from={}&to={}&amount={}", target, my_account2, 1_000_000);
	//                        01234  5678  90123456
	// (1) send a request from one attack account to another attacker account
	let request = client.transfer_request_iv(my_account2, 1_000_000);
	println!("{}", server.process_iv_request(request.clone()));

	// (2) use the captured request string to create a new request to steal money!
	let iv_start = request.len() - 32 * 2;
	let iv_end = request.len() - 16 * 2;
	let og_iv = byte_str_to_bytes(&request[iv_start..iv_end]);
	// new_iv = og_iv ^ request[..16] ^ desired_request[..16]
	let iv = xor(&og_iv, &xor(&request[..16], pre_iv.as_bytes()))[..16].to_hex_string();

	let mut new_request = pre_iv.as_bytes().to_vec();
	new_request.extend_from_slice(iv.as_bytes());
	new_request.extend_from_slice(&request[iv_end..]);

	// (3) profit!!
	println!("{}", server.process_iv_request(new_request));


	// PART 2 - this must involve not making some assumption that i'm making
	//          because I'm not sure how to break this
}

