///
///  Sample Rust program to use dlccryptlib.
///

#[cfg(test)]
mod test_lib;

use dlccryptlib;

fn main() {
    println!("Dlccryptlib sample (Rust)");

    let entropy_hex = "00000000000000000000000000000001"; // abandon x 11 actual
    let network = "signet";

    let xpub = dlccryptlib::init_with_entropy(entropy_hex, network).unwrap();
    println!("xpub: {xpub}");

    let pubkey0 = dlccryptlib::get_public_key(0, 0).unwrap();
    println!("pubkey 0: {pubkey0}");

    let hash = "0001020300000000000000000000000000000000000000000000000000010203";
    let sig = dlccryptlib::sign_hash_ecdsa(hash, 0, 0, &pubkey0).unwrap();
    println!("signature: {sig}");
}
