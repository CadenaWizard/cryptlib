///
///  Sample Rust program to use dlccryptlib.
///
use dlccryptlib;

const DUMMY_ENTROPY_STR: &str = "00000000000000000000000000000001";
const DUMMY_HASH07_STR: &str = "0000000000000000000000000000000000000000000000000000000000000007";
const NETWORK_SIGNET: &str = "signet";
const DEFAULT_NETWORK: &str = NETWORK_SIGNET;

#[test]
fn test_init_with_entropy() {
    let xpub = dlccryptlib::init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();
    assert_eq!(
            xpub,
            "tpubDCxVvuZwEu4oZypCT3pzos1MUoVJyjTHjfrhKFXNBkAEqBmkkzEb2dUgzpZmBWbd6wZnNmm3Ex2suMnEFUMmayH2a6S49R4pTnoQttGrxUm"
        );
}

#[test]
fn test_get_public_key() {
    let _xpub = dlccryptlib::init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();

    let pubkey0 = dlccryptlib::get_public_key(0).unwrap();
    assert_eq!(
        pubkey0.to_string(),
        "031941e84b8d111e094aefc46e7181757c93a1da87c93ab519a40d9d765176e704"
    );

    let pubkey3 = dlccryptlib::get_public_key(3).unwrap();
    assert_eq!(
        pubkey3.to_string(),
        "02a9569875400df2b7af9360fc5025de31fcd48ca8b658d61e535c3ff2f55aa128"
    );
}

#[test]
fn test_sign_hash_ecdsa() {
    let _xpub = dlccryptlib::init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();

    let pubkey3 = dlccryptlib::get_public_key(3).unwrap();
    assert_eq!(
        pubkey3.to_string(),
        "02a9569875400df2b7af9360fc5025de31fcd48ca8b658d61e535c3ff2f55aa128"
    );

    let hash = DUMMY_HASH07_STR;
    let sig = dlccryptlib::sign_hash_ecdsa(&hash, 3, &pubkey3).unwrap();

    assert!(sig.len() >= 140 && sig.len() <= 146);

    // negative test, wrong index
    assert!(dlccryptlib::sign_hash_ecdsa(&hash, 31, &pubkey3).is_err());
}
