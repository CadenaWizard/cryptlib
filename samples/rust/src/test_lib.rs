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

    let pubkey00 = dlccryptlib::get_public_key(0, 0).unwrap();
    assert_eq!(
        pubkey00.to_string(),
        "031941e84b8d111e094aefc46e7181757c93a1da87c93ab519a40d9d765176e704"
    );

    let pubkey03 = dlccryptlib::get_public_key(0, 3).unwrap();
    assert_eq!(
        pubkey03.to_string(),
        "02a9569875400df2b7af9360fc5025de31fcd48ca8b658d61e535c3ff2f55aa128"
    );

    let pubkey10 = dlccryptlib::get_public_key(1, 0).unwrap();
    assert_eq!(
        pubkey10.to_string(),
        "026f48799f8f6571a6b8d1f8737f4ca9f2b73aa7597ee8766120cac4cee222a603"
    );
}

#[test]
fn test_sign_hash_ecdsa() {
    let _xpub = dlccryptlib::init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();

    let pubkey3 = dlccryptlib::get_public_key(0, 3).unwrap();
    assert_eq!(
        pubkey3.to_string(),
        "02a9569875400df2b7af9360fc5025de31fcd48ca8b658d61e535c3ff2f55aa128"
    );

    let hash = DUMMY_HASH07_STR;
    let sig = dlccryptlib::sign_hash_ecdsa(&hash, 0, 3, &pubkey3).unwrap();

    assert!(sig.len() >= 140 && sig.len() <= 146);

    // negative test, wrong index
    assert!(dlccryptlib::sign_hash_ecdsa(&hash, 0, 31, &pubkey3).is_err());
    assert!(dlccryptlib::sign_hash_ecdsa(&hash, 1, 3, &pubkey3).is_err());
}

#[test]
fn test_derived_nonces() {
    let _xpub = dlccryptlib::init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();
    let oracle_pubkey = dlccryptlib::get_public_key(0, 0).unwrap();
    let event_id = "btcusd1741474920";
    let template = "Outcome:btcusd1741474920:{digit_index}:{digit_outcome}";

    let nonces = dlccryptlib::create_derived_nonces(0, 0, &oracle_pubkey, event_id, 4).unwrap();
    assert_eq!(nonces.split(" ").count(), 4);
    // Deterministic
    assert_eq!(
        dlccryptlib::create_derived_nonces(0, 0, &oracle_pubkey, event_id, 4).unwrap(),
        nonces
    );
    assert!(
        dlccryptlib::verify_derived_nonces(0, 0, &oracle_pubkey, event_id, 4, &nonces).unwrap()
    );
    assert!(
        !dlccryptlib::verify_derived_nonces(0, 0, &oracle_pubkey, "other_event", 4, &nonces)
            .unwrap()
    );

    let attestation = dlccryptlib::sign_attestation_with_derived_nonces(
        0,
        0,
        &oracle_pubkey,
        event_id,
        4,
        template,
        "9534",
        &nonces,
    )
    .unwrap();
    let sigs: Vec<_> = attestation.split(" ").collect();
    assert_eq!(sigs.len(), 4);
    assert!(dlccryptlib::verify_schnorr("Outcome:btcusd1741474920:0:9", sigs[0], 0, 0).unwrap());

    // negative test, wrong index for the pubkey
    assert!(dlccryptlib::create_derived_nonces(0, 1, &oracle_pubkey, event_id, 4).is_err());
}
