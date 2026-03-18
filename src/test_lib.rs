// Copyright (c) 2025-present Cadena Bitcoin
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::adaptor_signature::verify_ecdsa_signature;
use crate::{
    combine_pubkeys, combine_seckeys, create_deterministic_nonce, get_public_key,
    init_with_entropy, keypair_from_sec_key_hex, sign_schnorr_with_nonce, verify_public_key,
    verify_schnorr, Lib,
};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::PublicKey;
use secp256k1_zkp::schnorr::Signature as SchnorrSignature;
use secp256k1_zkp::EcdsaAdaptorSignature;
use std::str::FromStr;

const DUMMY_ENTROPY_STR: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const NETWORK_MAINNET: &str = "bitcoin";
const NETWORK_SIGNET: &str = "signet";
const DEFAULT_NETWORK: &str = NETWORK_SIGNET;

fn dummy_bytes32(last_byte: u8) -> [u8; 32] {
    let mut b = [0; 32];
    b[31] = last_byte;
    b
}

fn dummy_entropy() -> Vec<u8> {
    dummy_bytes32(0).to_vec()
}

#[test]
fn test_init_with_entropy_lib() {
    let mut lib = Lib::new_empty();
    let _ = lib
        .init_with_entropy(&dummy_entropy(), DEFAULT_NETWORK)
        .unwrap();
    let xpub = lib.get_xpub().unwrap().to_string();
    assert_eq!(
            xpub,
            "tpubDCWivZp6qaqCALCt8MyLqAb3awnWm4hfbBPjdZqirYFXYeZ5YsfbWVaPacULZTGtK1RPBSZ92UWNjnhL4fB9UVrF2FjgW8cgmBjxPBmB4iB"
        );
}

#[test]
fn test_init_with_entropy_lib_mainnet() {
    let mut lib = Lib::new_empty();
    let _ = lib
        .init_with_entropy(&dummy_entropy(), NETWORK_MAINNET)
        .unwrap();
    let xpub = lib.get_xpub().unwrap().to_string();
    assert_eq!(
            xpub,
            "xpub6Bner3L3tdQW367NmmMsWKtMfP7hbu4JxdtbSGdWWjSzLkSUEnT7G9h5GFWUXtifeRhHiUXJuek1qeaTJqnXkveWpiHp8rmt53E8HTMshg9"
        );
}

#[test]
fn test_get_public_key() {
    let _xpub = init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();

    let pubkey00 = get_public_key(0, 0).unwrap();
    assert_eq!(
        pubkey00.to_string(),
        "0298720ece754e377af1b2716256e63c2e2427ff6ebdc66c2071c43ae80132ca32"
    );

    let pubkey03 = get_public_key(0, 3).unwrap();
    assert_eq!(
        pubkey03.to_string(),
        "03b74dc470965932fc976459096526b08a0f939a95e4b72db8f9aadce18a08a72e"
    );

    let pubkey10 = get_public_key(1, 0).unwrap();
    assert_eq!(
        pubkey10.to_string(),
        "02eb2522e05e5b4656aec2e97c85b57c2a9e2c036f4843ae4a21322fe4e6aabcaf"
    );
}

#[test]
fn test_verify_public_key() {
    let _xpub = init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();

    assert!(verify_public_key(
        0,
        0,
        "0298720ece754e377af1b2716256e63c2e2427ff6ebdc66c2071c43ae80132ca32"
    )
    .unwrap());
    assert_eq!(verify_public_key(0, 0, "03b74dc470965932fc976459096526b08a0f939a95e4b72db8f9aadce18a08a72e").err().unwrap(),
            "Pubkey mismatch, index 0/0, 03b74dc470965932fc976459096526b08a0f939a95e4b72db8f9aadce18a08a72e vs. 0298720ece754e377af1b2716256e63c2e2427ff6ebdc66c2071c43ae80132ca32");

    assert!(verify_public_key(
        0,
        3,
        "03b74dc470965932fc976459096526b08a0f939a95e4b72db8f9aadce18a08a72e"
    )
    .unwrap());
    assert_eq!(verify_public_key(0, 3, "0298720ece754e377af1b2716256e63c2e2427ff6ebdc66c2071c43ae80132ca32").err().unwrap(),
            "Pubkey mismatch, index 0/3, 0298720ece754e377af1b2716256e63c2e2427ff6ebdc66c2071c43ae80132ca32 vs. 03b74dc470965932fc976459096526b08a0f939a95e4b72db8f9aadce18a08a72e");

    assert!(verify_public_key(
        1,
        0,
        "02eb2522e05e5b4656aec2e97c85b57c2a9e2c036f4843ae4a21322fe4e6aabcaf"
    )
    .unwrap());
    assert_eq!(verify_public_key(1, 0, "03b74dc470965932fc976459096526b08a0f939a95e4b72db8f9aadce18a08a72e").err().unwrap(),
            "Pubkey mismatch, index 1/0, 03b74dc470965932fc976459096526b08a0f939a95e4b72db8f9aadce18a08a72e vs. 02eb2522e05e5b4656aec2e97c85b57c2a9e2c036f4843ae4a21322fe4e6aabcaf");
}

#[test]
fn test_sign_hash_ecdsa() {
    let mut lib = Lib::new_empty();
    let _xpub = lib
        .init_with_entropy(&dummy_entropy(), DEFAULT_NETWORK)
        .unwrap();

    let pubkey3 = lib.get_child_public_key(0, 3).unwrap();
    assert_eq!(
        pubkey3.to_string(),
        "03b74dc470965932fc976459096526b08a0f939a95e4b72db8f9aadce18a08a72e"
    );

    let hash = dummy_bytes32(7);
    let sig = lib.sign_hash_ecdsa(&hash, 0, 3, &pubkey3).unwrap();

    // verify_signature
    let verif_res = verify_ecdsa_signature(&hash, &sig, &pubkey3, true).unwrap();
    assert!(verif_res);

    // negative test, wrong index
    assert!(lib.sign_hash_ecdsa(&hash, 0, 31, &pubkey3).is_err());
    assert!(lib.sign_hash_ecdsa(&hash, 1, 3, &pubkey3).is_err());
}

#[test]
fn test_create_deterministic_nonce() {
    let (sk1, pk1) = create_deterministic_nonce("event01", 0).unwrap();
    assert_eq!(sk1.len(), 64);
    assert_eq!(pk1.len(), 66);
    assert_ne!(sk1, pk1);
    let (sk2, pk2) = create_deterministic_nonce("event01", 1).unwrap();
    assert_ne!(sk1, sk2);
    assert_ne!(pk1, pk2);
}

#[test]
fn test_sign_schnorr_with_nonce() {
    let _xpub = init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();

    let msg = "This is a message";
    let nonce = "0123450000000000006897528962743076432965432697856340567500000100";
    let sig = sign_schnorr_with_nonce(msg, nonce, 0, 0).unwrap();
    let expected_sig = "ff4cb99e0a9be8ec7dea1e51904cf22f71717c19fc3e7dcbc8346eb28bebffbb892c4c41e05c2383efda00f5acc9c7f3622d88a90630cd62d49db598c8ce10b9";
    assert_eq!(sig.len(), 128);
    assert_eq!(sig.to_string(), expected_sig);

    // sign again
    let sig2 = sign_schnorr_with_nonce(msg, nonce, 0, 0).unwrap();
    assert_eq!(sig2.to_string(), expected_sig);

    // sign with different nonce
    let nonce2 = "0123450000000000006897528962743076432965432697856340567500000199";
    let sig3 = sign_schnorr_with_nonce(msg, nonce2, 0, 0).unwrap();
    assert_eq!(sig3.to_string(), "4578740620e7a2c56eabea07c835dba35e832115930d023d0a7778652fbbf7d97a9f4a207dcb1456f1b0f57c4856085c32c79f4efce81cd276c272190aab5e3c");
}

#[test]
fn test_verify_schnorr() {
    let _xpub = init_with_entropy(DUMMY_ENTROPY_STR, DEFAULT_NETWORK).unwrap();

    let msg = "This is a message";

    // Constant signature
    let sig1 = "ff4cb99e0a9be8ec7dea1e51904cf22f71717c19fc3e7dcbc8346eb28bebffbb892c4c41e05c2383efda00f5acc9c7f3622d88a90630cd62d49db598c8ce10b9";
    let verify_res = verify_schnorr(msg, &sig1, 0, 0).unwrap();
    assert_eq!(verify_res, true);

    // Signature created here
    let nonce = "0123450000000000006897528962743076432965432697856340567500000100";
    let sig = sign_schnorr_with_nonce(msg, nonce, 0, 0).unwrap();

    let verify_res = verify_schnorr(msg, &sig, 0, 0).unwrap();
    assert_eq!(verify_res, true);

    // Verify with different key index
    let verify_res = verify_schnorr(msg, &sig, 0, 1).unwrap();
    assert_eq!(verify_res, false);
    let verify_res = verify_schnorr(msg, &sig, 1, 0).unwrap();
    assert_eq!(verify_res, false);

    // Verify with a different message
    let msg2 = "This is ANOTHER message";
    let verify_res = verify_schnorr(msg2, &sig, 0, 0).unwrap();
    assert_eq!(verify_res, false);
}

fn create_dummy_pubkey(index: u8) -> PublicKey {
    let sechex = format!(
        "012345000000000000689752896274307643296543269785634056750000000{}",
        index
    );
    assert_eq!(sechex.len(), 64);
    let keypair = keypair_from_sec_key_hex(&sechex).unwrap();
    keypair.public_key()
}

#[test]
fn test_combine_pubkeys() {
    let mut input_str = String::new();
    for i in 0..3 {
        input_str += &(create_dummy_pubkey(i).to_string() + " ");
    }
    let combined = combine_pubkeys(&input_str).unwrap();
    assert_eq!(
        combined,
        "030d7a38fb6eab9933efd3149f7ce0c466e93eb0680442856acb664719b60ae977"
    );
}

#[test]
fn test_combine_seckeys() {
    let input_str = "0123450000000000006897528962743076432965432697856340567500000100 \
            0123450000000000006897528962743076432965432697856340567500000200 \
            0123450000000000006897528962743076432965432697856340567500000300";
    let combined = combine_seckeys(input_str).unwrap();
    assert_eq!(
        combined,
        "0369cf00000000000139c5f79c275c9162c97c2fc973c69029c1035f00000600"
    );
}

#[test]
fn test_create_cet_adaptor_sigs() {
    let mut lib = Lib::new_empty();
    let _xpub = lib.init_with_entropy(&dummy_bytes32(0).to_vec(), DEFAULT_NETWORK);

    let nonces = vec![
        create_dummy_pubkey(0),
        create_dummy_pubkey(1),
        create_dummy_pubkey(2),
        create_dummy_pubkey(3),
        create_dummy_pubkey(4),
        create_dummy_pubkey(5),
    ];
    let interval_wildcards = vec![
        "001****".to_string(),
        "002****".to_string(),
        "003****".to_string(),
    ];
    let sighashes = vec![dummy_bytes32(0), dummy_bytes32(1), dummy_bytes32(2)];
    let oracle_pubkey = create_dummy_pubkey(9);
    let my_pubkey = lib.get_child_public_key(0, 0).unwrap();
    assert_eq!(
        my_pubkey.to_string(),
        "0298720ece754e377af1b2716256e63c2e2427ff6ebdc66c2071c43ae80132ca32"
    );

    let adaptor_sigs_vec = lib
        .create_cet_adaptor_sigs(
            6, // num_digits
            3, // num_cets
            "Outcome:btcusd1741474920:{digit_index}:{digit_outcome}",
            &oracle_pubkey,
            0,
            0,
            &my_pubkey,
            &nonces,
            &interval_wildcards,
            &sighashes,
        )
        .unwrap();
    assert_eq!(adaptor_sigs_vec.len(), 3);
    // adaptor sigs are variable, cannot assert
}

#[test]
fn test_verify_cet_adaptor_sigs_full() {
    let mut lib = Lib::new_empty();
    let _xpub = lib.init_with_entropy(&dummy_bytes32(0).to_vec(), DEFAULT_NETWORK);

    let nonces = vec![
        create_dummy_pubkey(0),
        create_dummy_pubkey(1),
        create_dummy_pubkey(2),
        create_dummy_pubkey(3),
        create_dummy_pubkey(4),
        create_dummy_pubkey(5),
    ];
    let interval_wildcards = vec![
        "001****".to_string(),
        "002****".to_string(),
        "003****".to_string(),
    ];
    let sighashes = vec![dummy_bytes32(0), dummy_bytes32(1), dummy_bytes32(2)];
    let oracle_pubkey = create_dummy_pubkey(9);
    let my_pubkey = lib.get_child_public_key(0, 0).unwrap();
    assert_eq!(
        my_pubkey.to_string(),
        "0298720ece754e377af1b2716256e63c2e2427ff6ebdc66c2071c43ae80132ca32"
    );

    // First create the signatures
    let adaptor_sigs_vec = lib
        .create_cet_adaptor_sigs(
            6, // num_digits
            3, // num_cets
            "Outcome:btcusd1741474920:{digit_index}:{digit_outcome}",
            &oracle_pubkey,
            0,
            0,
            &my_pubkey,
            &nonces,
            &interval_wildcards,
            &sighashes,
        )
        .unwrap();
    assert_eq!(adaptor_sigs_vec.len(), 3);

    // Verify the signatures
    let _res = lib
        .verify_cet_adaptor_sigs(
            6,
            3,
            "Outcome:btcusd1741474920:{digit_index}:{digit_outcome}",
            &oracle_pubkey,
            &my_pubkey,
            &nonces,
            &interval_wildcards,
            &sighashes,
            &adaptor_sigs_vec,
        )
        .unwrap();
}

#[test]
fn test_verify_cet_adaptor_sigs() {
    let nonces = vec![
        create_dummy_pubkey(0),
        create_dummy_pubkey(1),
        create_dummy_pubkey(2),
        create_dummy_pubkey(3),
        create_dummy_pubkey(4),
        create_dummy_pubkey(5),
    ];
    let interval_wildcards = vec![
        "001****".to_string(),
        "002****".to_string(),
        "003****".to_string(),
    ];
    let sighashes = vec![dummy_bytes32(0), dummy_bytes32(1), dummy_bytes32(2)];
    let oracle_pubkey = create_dummy_pubkey(9);
    let my_pubkey =
        PublicKey::from_str("0298720ece754e377af1b2716256e63c2e2427ff6ebdc66c2071c43ae80132ca32")
            .unwrap();
    let adaptor_sigs_vec = vec![
        EcdsaAdaptorSignature::from_str("02c601b771f535d1df127de6f67289d783d0af9237c6330b95f19b8ced14c04ecf039708a6953eb8f02353b43858f11f58c03d0b6f02e2dac91389694168e8f52f5fc6e00105830f4fea83a1e68da30b2ebd382a64e8c5548227a58b104091f863a28bb081f94ac28ce937cbb3e3c0fe6c0281672d3954025ee53eb4e3d6bc771cbde7494187bc55a29a81be71c63d7e7bff714a2623e08fc00d7cac7583cd9685da").unwrap(),
        EcdsaAdaptorSignature::from_str("02b1eaaa7be0e71c940bcb4fb34a12dad37c870774d0530a2b7d800bbed708b42e03d3934b492ff04e29cb7e490d1bb5b98ff7b6b0449f3ca80372845b94c70ed30e83a05ecccf8ab354763265bd65a6ed6b54808a3145341edfd4bc15a980e5b0089cafa97d0f1425d46162d5958e7da17dac4251ad7421a9b31de1d89ccf4e92d1328457e02cf698884d2539d6defe02e924c05e967ddef72162ee3a018a959a6a").unwrap(),
        EcdsaAdaptorSignature::from_str("02c713d865019906ea3588814896311993a7417b5cb51746f811632bfa7f04b69f02e6d18c4dd8b873ebd3948429ece734f548d38b7f699839c6805a434422a8154bdac5695f9f9921fc8b087a976e36bad9135b6a4290bf1018a7879c594fd4f9fd39b7e9a953a0befab3bcc73e3ffd16fefd00620221954d1618a7220dc784d2059900add8d84745fc34d6fc6ff57b05853b62ad988dcaeb2324d4b5b2c15e4643").unwrap(),
    ];

    let lib = Lib::new_empty();
    // Verify the signatures
    let _res = lib
        .verify_cet_adaptor_sigs(
            6,
            3,
            "Outcome:btcusd1741474920:{digit_index}:{digit_outcome}",
            &oracle_pubkey,
            &my_pubkey,
            &nonces,
            &interval_wildcards,
            &sighashes,
            &adaptor_sigs_vec,
        )
        .unwrap();
}

#[test]
fn test_create_final_cet_sigs_full() {
    let event_id = "btcusd1741474920";
    let digits_template_string = "Outcome:btcusd1741474920:{digit_index}:{digit_outcome}";
    let digits = 4 as u8;
    let final_cet_wildcard = "9534";
    let sighash = dummy_bytes32(7);

    // First preparation: create oracle signatures
    let mut lib_ora = Lib::new_empty();
    let _xpub = lib_ora.init_with_entropy(&dummy_bytes32(3).to_vec(), DEFAULT_NETWORK);
    let oracle_pubkey = lib_ora.get_child_public_key(0, 0).unwrap();
    assert_eq!(
        oracle_pubkey.to_string(),
        "020a5e571a47cc259d3cc0454a8b7e58bba16e01156bb72d0ce490823f51117cce"
    );

    // Prepare nonces
    let mut nonces_sec_vec = Vec::new();
    let mut nonces_pub_vec = Vec::new();
    let mut nonces = String::new();
    for i in 0..(digits as usize) {
        let (nsec, npub) = lib_ora
            .create_deterministic_nonce(event_id, i as u32)
            .unwrap();
        nonces_sec_vec.push(<[u8; 32]>::from_hex(&nsec).unwrap());
        nonces_pub_vec.push(npub.clone());
        nonces += &format!("{} ", npub);
    }
    assert_eq!(nonces, "03829589a7db8530b521577ce5b9560e31cb29b943927b417c580ec3b6e57317a9 0278d6b6808d5370da62c9304f66415c1f9f408a2ee9d95a9dc836512218a7b04f 027c14675c2bd2e728e5760d5017d4ae2b22a4a33193689654e5eb13111ab7f491 02e7657c7d006d27b248642974875348b41299690a6415bc019ac71e6988434daa ");

    let mut oracle_signatures = Vec::new();
    for i in 0..(digits as usize) {
        let digit_value = final_cet_wildcard.chars().collect::<Vec<_>>()[i as usize];
        let digit_string = digits_template_string
            .replace("{digit_index}", &format!("{}", i))
            .replace("{digit_outcome}", &format!("{}", digit_value));
        let sig = lib_ora
            .sign_schnorr_with_nonce(&digit_string, &nonces_sec_vec[i], 0, 0)
            .unwrap();
        oracle_signatures.push(sig);
    }

    // Second, create adaptor sig of other
    let mut lib2 = Lib::new_empty();
    let _xpub = lib2
        .init_with_entropy(&dummy_bytes32(2).to_vec(), DEFAULT_NETWORK)
        .unwrap();
    let other_pubkey = lib2.get_child_public_key(0, 0).unwrap();
    assert_eq!(
        other_pubkey.to_string(),
        "02142c5af97c4afd91bea47ac47e56fad2935dcacc04b3ffa69e5ff7760cbd07ed"
    );

    // only use one CET
    let other_adaptor_sigs_vec = lib2
        .create_cet_adaptor_sigs(
            digits,
            1, // num_cets
            digits_template_string,
            &oracle_pubkey,
            0,
            0,
            &other_pubkey,
            &nonces_pub_vec,
            &vec![final_cet_wildcard.to_string()], // interval_wildcards
            &vec![sighash],
        )
        .unwrap();
    let other_adaptor_sig = other_adaptor_sigs_vec[0];
    // adator sig is variable, cannot assert
    assert_eq!(other_adaptor_sig.to_string().len(), 324);

    // Now back to ourselves
    let mut lib1 = Lib::new_empty();
    let _xpub = lib1
        .init_with_entropy(&dummy_bytes32(1).to_vec(), DEFAULT_NETWORK)
        .unwrap();
    let my_pubkey = lib1.get_child_public_key(0, 0).unwrap();
    assert_eq!(
        my_pubkey.to_string(),
        "035bcac7323e9971268213a188d8268277abcd962cdf096e68e2b58c228216f104"
    );

    let final_sigs = lib1
        .create_final_cet_sigs(
            0,
            0,
            &my_pubkey,
            &other_pubkey,
            digits,
            &oracle_signatures,
            final_cet_wildcard,
            &sighash,
            &other_adaptor_sig,
        )
        .unwrap();
    let sig_of_other = final_sigs.0;
    let my_sig = final_sigs.1;

    // verify_signatures
    let verif_res1 = verify_ecdsa_signature(&sighash, &sig_of_other, &other_pubkey, true).unwrap();
    assert!(verif_res1);
    let verif_res2 = verify_ecdsa_signature(&sighash, &my_sig, &my_pubkey, true).unwrap();
    assert!(verif_res2);
}

#[test]
fn test_create_final_cet_sigs() {
    let digits = 4 as u8;
    let final_cet_wildcard = "9534";
    let sighash = dummy_bytes32(7);
    let oracle_signatures = vec![
        SchnorrSignature::from_str("829589a7db8530b521577ce5b9560e31cb29b943927b417c580ec3b6e57317a91e36a673186742bd75a85f6751473fd10155f44fec71a62e95ca6e2f6a436de6").unwrap(),
        SchnorrSignature::from_str("78d6b6808d5370da62c9304f66415c1f9f408a2ee9d95a9dc836512218a7b04fd67ccbe7eefd9cd96c396a64b5ddc8e6a42d82e8e753ced18e162d238787da50").unwrap(),
        SchnorrSignature::from_str("7c14675c2bd2e728e5760d5017d4ae2b22a4a33193689654e5eb13111ab7f491f5889b410410014ddc5bef26d55b3cfd6f3c0bec338fc8c29edc323da3e301e1").unwrap(),
        SchnorrSignature::from_str("e7657c7d006d27b248642974875348b41299690a6415bc019ac71e6988434daaf722c5e3e015c26180d7a5e5543f6668297d188536e98b9de6313df4c5ca5f60").unwrap(),
    ];
    let other_pubkey =
        PublicKey::from_str("02142c5af97c4afd91bea47ac47e56fad2935dcacc04b3ffa69e5ff7760cbd07ed")
            .unwrap();
    let other_adaptor_sig = EcdsaAdaptorSignature::from_str("0287b5a935d349eca94eaa9c8362abcde778b215754a195163d519317a5df551ef03b43cc062377901a906fb6c9c67837def8f21bc0117159724a1047c25ef97dde2ebff6c23fc0fe43c59f1771e4ed9c44e27f4e03d04f57287e15e2646563d9c1fb152e0e137bb990b8b14f16006d8493964303ac265c108c2c9ac10e3a7917a2e86ba49455802a18c72c57d8e660f982984f5bd0e792a68f2b2c2c7a4882604d4").unwrap();

    let mut lib = Lib::new_empty();
    let _xpub = lib
        .init_with_entropy(&dummy_bytes32(1).to_vec(), DEFAULT_NETWORK)
        .unwrap();
    let my_pubkey = lib.get_child_public_key(0, 0).unwrap();
    assert_eq!(
        my_pubkey.to_string(),
        "035bcac7323e9971268213a188d8268277abcd962cdf096e68e2b58c228216f104"
    );

    let final_sigs = lib
        .create_final_cet_sigs(
            0,
            0,
            &my_pubkey,
            &other_pubkey,
            digits,
            &oracle_signatures,
            final_cet_wildcard,
            &sighash,
            &other_adaptor_sig,
        )
        .unwrap();
    let sig_of_other = final_sigs.0;
    let my_sig = final_sigs.1;

    // verify_signatures
    let verif_res1 = verify_ecdsa_signature(&sighash, &sig_of_other, &other_pubkey, true).unwrap();
    assert!(verif_res1);
    let verif_res2 = verify_ecdsa_signature(&sighash, &my_sig, &my_pubkey, true).unwrap();
    assert!(verif_res2);
}

#[test]
fn test_create_final_cet_sig_full() {
    let event_id = "btcusd1741474920";
    let digits_template_string = "Outcome:btcusd1741474920:{digit_index}:{digit_outcome}";
    let digits = 4 as u8;
    let final_cet_wildcard = "9534";
    let sighash = dummy_bytes32(7);

    // First preparation: create oracle signatures
    let mut lib_ora = Lib::new_empty();
    let _xpub = lib_ora.init_with_entropy(&dummy_bytes32(3).to_vec(), DEFAULT_NETWORK);
    let oracle_pubkey = lib_ora.get_child_public_key(0, 0).unwrap();
    assert_eq!(
        oracle_pubkey.to_string(),
        "020a5e571a47cc259d3cc0454a8b7e58bba16e01156bb72d0ce490823f51117cce"
    );

    // Prepare nonces
    let mut nonces_sec_vec = Vec::new();
    let mut nonces_pub_vec = Vec::new();
    let mut nonces = String::new();
    for i in 0..(digits as usize) {
        let (nsec, npub) = lib_ora
            .create_deterministic_nonce(event_id, i as u32)
            .unwrap();
        nonces_sec_vec.push(<[u8; 32]>::from_hex(&nsec).unwrap());
        nonces_pub_vec.push(npub.clone());
        nonces += &format!("{} ", npub);
    }
    assert_eq!(nonces, "03829589a7db8530b521577ce5b9560e31cb29b943927b417c580ec3b6e57317a9 0278d6b6808d5370da62c9304f66415c1f9f408a2ee9d95a9dc836512218a7b04f 027c14675c2bd2e728e5760d5017d4ae2b22a4a33193689654e5eb13111ab7f491 02e7657c7d006d27b248642974875348b41299690a6415bc019ac71e6988434daa ");

    let mut oracle_signatures = Vec::new();
    for i in 0..(digits as usize) {
        let digit_value = final_cet_wildcard.chars().collect::<Vec<_>>()[i as usize];
        let digit_string = digits_template_string
            .replace("{digit_index}", &format!("{}", i))
            .replace("{digit_outcome}", &format!("{}", digit_value));
        let sig = lib_ora
            .sign_schnorr_with_nonce(&digit_string, &nonces_sec_vec[i], 0, 0)
            .unwrap();
        oracle_signatures.push(sig);
    }

    let mut lib1 = Lib::new_empty();
    let _xpub = lib1
        .init_with_entropy(&dummy_bytes32(1).to_vec(), DEFAULT_NETWORK)
        .unwrap();
    let my_pubkey = lib1.get_child_public_key(0, 0).unwrap();
    assert_eq!(
        my_pubkey.to_string(),
        "035bcac7323e9971268213a188d8268277abcd962cdf096e68e2b58c228216f104"
    );

    // Create adaptor sig
    // only use one CET
    let adaptor_sigs_vec = lib1
        .create_cet_adaptor_sigs(
            digits,
            1, // num_cets
            digits_template_string,
            &oracle_pubkey,
            0,
            0,
            &my_pubkey,
            &nonces_pub_vec,
            &vec![final_cet_wildcard.to_string()], // interval_wildcards
            &vec![sighash],
        )
        .unwrap();
    let adaptor_sig = adaptor_sigs_vec[0];
    // adator sig is variable, cannot assert
    assert_eq!(adaptor_sig.to_string().len(), 324);

    // And now decode the CET signature
    let my_final_sig = lib1
        .create_final_cet_sig(
            &my_pubkey,
            digits,
            &oracle_signatures,
            final_cet_wildcard,
            &sighash,
            &adaptor_sig,
        )
        .unwrap();
    // Result is variable, cannot assert
    assert!(my_final_sig.len() >= 70 && my_final_sig.len() <= 72);
}

#[test]
fn test_create_final_cet_sig() {
    let digits = 4 as u8;
    let final_cet_wildcard = "9534";
    let sighash = dummy_bytes32(7);
    let oracle_signatures = vec![
        SchnorrSignature::from_str("829589a7db8530b521577ce5b9560e31cb29b943927b417c580ec3b6e57317a91e36a673186742bd75a85f6751473fd10155f44fec71a62e95ca6e2f6a436de6").unwrap(),
        SchnorrSignature::from_str("78d6b6808d5370da62c9304f66415c1f9f408a2ee9d95a9dc836512218a7b04fd67ccbe7eefd9cd96c396a64b5ddc8e6a42d82e8e753ced18e162d238787da50").unwrap(),
        SchnorrSignature::from_str("7c14675c2bd2e728e5760d5017d4ae2b22a4a33193689654e5eb13111ab7f491f5889b410410014ddc5bef26d55b3cfd6f3c0bec338fc8c29edc323da3e301e1").unwrap(),
        SchnorrSignature::from_str("e7657c7d006d27b248642974875348b41299690a6415bc019ac71e6988434daaf722c5e3e015c26180d7a5e5543f6668297d188536e98b9de6313df4c5ca5f60").unwrap(),
    ];
    let my_pubkey =
        PublicKey::from_str("035bcac7323e9971268213a188d8268277abcd962cdf096e68e2b58c228216f104")
            .unwrap();
    let adaptor_sig = EcdsaAdaptorSignature::from_str("02b916af8ad219724712ec349ed2a0cb200efe228b8ad4bcbe048aa41d687b07c5039325102a25ead4dd1ce4cccd0fe49d444c041a2f230ee0469eb3f3cf34efe41deb736f677a9fbd248e8fcd6afae74c418fc8f791075f62d9ec66f03a761be15b7e803a66e5b57db2920cfaf5343bd68027ca01689967aa316c2af9ca75c35e68338436fb24963572af2cc762b8666653645282569b16997324cf884375ca6684").unwrap();

    let lib = Lib::new_empty();
    let final_sig = lib
        .create_final_cet_sig(
            &my_pubkey,
            digits,
            &oracle_signatures,
            final_cet_wildcard,
            &sighash,
            &adaptor_sig,
        )
        .unwrap();
    assert_eq!(final_sig.to_lower_hex_string(), "3045022100b916af8ad219724712ec349ed2a0cb200efe228b8ad4bcbe048aa41d687b07c502202fe73c65c04abd4394375f4225ae11e0dfad77362898497e4d79b0df0b2b8fdf01");
}
