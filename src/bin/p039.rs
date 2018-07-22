extern crate ooga;
use ooga::rsa::Rsa;

fn main() {
	let rsa = Rsa::new();
	let msg = "Stop collaborate and listen! Ice is back with a brand new edition. I flow like a hawk both daily and nightly".to_string();
	println!("sending secret message: {}", msg);
	let ct = rsa.enc_str(msg).unwrap();

	println!("------SECRET MESSAGE IN TRANSIT------");
	println!("encrypted: {:?}", ct);
	println!();
	println!();
	let msg = rsa.dec(ct);
	println!("recovered message: {:?}", String::from_utf8(msg));
}

