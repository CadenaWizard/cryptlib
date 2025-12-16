///
///  Sample Rust program to use dlccryptlib.
///
use dlccryptlib;

fn main() {
    println!("Dlccryptlib sample (Rust)");

    let entropy_hex = "99d33a674ce99d33a674ce99d33a674c"; // oil x 12
    let network = "signet";

    let xpub = dlccryptlib::init_with_entropy_intern(entropy_hex, network).unwrap();
    println!("xpub: {xpub}");

    let pubkey0 = dlccryptlib::get_public_key_intern(0).unwrap();
    println!("pubkey 0: {pubkey0}");

    let hash = "0001020300000000000000000000000000000000000000000000000000010203";
    let sig = dlccryptlib::sign_hash_ecdsa_intern(hash, 0, &pubkey0).unwrap();
    println!("signature: {sig}");
}
