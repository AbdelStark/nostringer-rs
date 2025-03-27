use nostr::prelude::*;

fn main() {
    println!("Hello, world!");
    // Generate new random keys
    let keys = Keys::generate();

    println!("Public key: {}", keys.public_key().to_hex());
    println!("Private key: {}", keys.secret_key().to_secret_hex());
}
