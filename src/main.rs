extern crate crypto;
extern crate rayon;

use std::fs::File;
use std::io::prelude::*;

use rayon::prelude::*;
use crypto::sha1::Sha1;
use crypto::digest::Digest;

struct IPv4Iterator {
	a: u8,
	b: Option<u8>,
	c: Option<u8>,
	d: Option<u8>,
}

impl IPv4Iterator {
	fn new() -> IPv4Iterator {
		IPv4Iterator {
			a: 0,
			b: None,
			c: None,
			d: None
		}
	}
	/// Skips over IP space that wouldn't ever possibly be relevant
	fn skips(&mut self) -> bool {
		match (self.a, self.b, self.c, self.d) {
			// First octet
			(0,..) | // this host
			(10,..) | // RFC1918
			(26,..) | (28,..) | (29,..) | (30,..) | // DoD 26/8, 28/8, 29/8, and 30/8
			(127,..) | // loopback
			(224..=239,..) | //multicast
			(240..=255,..) // useless future use
			=> { self.a += 1; return true; }
			// Second octet
			(100, Some(64..=127),..) | // CGNAT
			(172, Some(16..=31),..) | // RFC1918
			(192, Some(168),..) | // RFC1918
			(198, Some(18..=19),..) // benchmarking
			=> {
				self.b = Some(self.b.unwrap()+1);
				return true;
			}
			// TODO the various /24s
			_ => return false
		}
	}
	fn step(&mut self) -> bool {
		if self.a == 255 && self.b == Some(255) && self.c == Some(255) && self.d == Some(255) {
			return false;
		}
		if self.d.is_some() && self.d != Some(255) { self.d = Some(self.d.unwrap()+1); }
		if self.d == Some(255) { self.d = None; self.c = Some(self.c.unwrap()+1); }
		if self.c == Some(255) { self.c = None; self.b = Some(self.b.unwrap()+1); }
		if self.b == Some(255) { self.b = None;	self.a +=1; }
		true
	}

}

impl Iterator for IPv4Iterator {
	type Item = String;
	fn next(&mut self) -> Option<Self::Item> {
		while self.skips() {}
		if self.b.is_none() {
			self.b = Some(0);
			return Some(format!("{}.*", self.a));
		} else if self.c.is_none() {
			self.c = Some(0);
			return Some(format!("{}.{}.*", self.a, self.b?));
		} else if self.d.is_none() {
			self.d = Some(0);
			return Some(format!("{}.{}.{}.*", self.a, self.b?, self.c?));
		} else {
			let ret = format!("{}.{}.{}.{}", self.a, self.b?, self.c?, self.d?);
			if self.step() {
				return Some(ret);
			} else {
				return None;
			}
		}
	}
}


fn main() -> std::io::Result<()> {
	let mut contents = String::new();
	{
		let mut file = File::open("blockedservers")?;
		file.read_to_string(&mut contents)?;
	}
	let mut hashes: Vec<&str> = contents.split('\n').collect();
	hashes.sort();
	//println!("{:?}", hashes);
	//return Ok(());
	let mut i = IPv4Iterator::new();
	i.par_bridge().for_each(|x| {	
		let mut hasher = Sha1::new();
		hasher.input_str(&x);
		let hex = hasher.result_str();
		if let Ok(_) = hashes.binary_search(&hex.as_str()) {
			println!("{} {}", hex, x);
		}
	});
	Ok(())
}
