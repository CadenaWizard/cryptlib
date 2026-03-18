use dlccryptlib;

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

// ##### Facade functions for easy Python invocations (pyo3/maturin)

/// Initialize the library, load secret from encrypted file. Return the XPUB.
#[pyfunction]
pub fn init(path_for_secret_file: String, encryption_password: String) -> PyResult<String> {
    dlccryptlib::init(&path_for_secret_file, &encryption_password, false)
        .map_err(|e| PyErr::new::<PyException, _>(e))
}

#[pyfunction]
pub fn reinit_for_testing(
    path_for_secret_file: String,
    encryption_password: String,
) -> PyResult<String> {
    dlccryptlib::init(&path_for_secret_file, &encryption_password, true)
        .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// network: "bitcoin", or "signet".
// #[cfg(test)]
#[pyfunction]
pub fn init_with_entropy(entropy: String, network: String) -> PyResult<String> {
    dlccryptlib::init_with_entropy(&entropy, &network).map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Return the XPUB
#[pyfunction]
pub fn get_xpub() -> PyResult<String> {
    dlccryptlib::get_xpub().map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Return a child public key (specified by its index).
#[pyfunction]
pub fn get_public_key(index4: u32, index5: u32) -> PyResult<String> {
    dlccryptlib::get_public_key(index4, index5).map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Return a child address (specified by index).
#[pyfunction]
pub fn get_address(index4: u32, index5: u32) -> PyResult<String> {
    dlccryptlib::get_address(index4, index5).map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Verify a child public key.
#[pyfunction]
pub fn verify_public_key(index4: u32, index5: u32, pubkey: String) -> PyResult<bool> {
    dlccryptlib::verify_public_key(index4, index5, &pubkey)
        .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Sign a hash with a child private key (specified by index).
#[pyfunction]
pub fn sign_hash_ecdsa(
    hash: String,
    signer_index4: u32,
    signer_index5: u32,
    signer_pubkey: String,
) -> PyResult<String> {
    dlccryptlib::sign_hash_ecdsa(&hash, signer_index4, signer_index5, &signer_pubkey)
        .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Create a nonce value deterministically
#[pyfunction]
pub fn create_deterministic_nonce(
    event_id: String,
    nonce_index: u32,
) -> PyResult<(String, String)> {
    dlccryptlib::create_deterministic_nonce(&event_id, nonce_index)
        .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Sign a message using Schnorr, with a nonce, using a child key
#[pyfunction]
pub fn sign_schnorr_with_nonce(
    msg: String,
    nonce_sec_hex: String,
    index4: u32,
    index5: u32,
) -> PyResult<String> {
    dlccryptlib::sign_schnorr_with_nonce(&msg, &nonce_sec_hex, index4, index5)
        .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Verify a Schnorr signature over a message, using a child key
#[pyfunction]
pub fn verify_schnorr(
    msg: String,
    signature_hex: String,
    index4: u32,
    index5: u32,
) -> PyResult<bool> {
    dlccryptlib::verify_schnorr(&msg, &signature_hex, index4, index5)
        .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Combine a number of public keys into one
#[pyfunction]
pub fn combine_pubkeys(keys_hex: String) -> PyResult<String> {
    dlccryptlib::combine_pubkeys(&keys_hex).map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Combine a number of secret keys into one.
/// Warning: Handle secret keys with caution!
#[pyfunction]
pub fn combine_seckeys(keys_hex: String) -> PyResult<String> {
    dlccryptlib::combine_seckeys(&keys_hex).map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Create adaptor signatures for a number of CETs
#[pyfunction]
pub fn create_cet_adaptor_sigs(
    num_digits: u8,
    num_cets: u64,
    digit_string_template: String,
    oracle_pubkey: String,
    signing_key_index4: u32,
    signing_key_index5: u32,
    signing_pubkey: String,
    nonces: String,
    interval_wildcards: String,
    sighashes: String,
) -> PyResult<String> {
    dlccryptlib::create_cet_adaptor_sigs(
        num_digits,
        num_cets,
        &digit_string_template,
        &oracle_pubkey,
        signing_key_index4,
        signing_key_index5,
        &signing_pubkey,
        &nonces,
        &interval_wildcards,
        &sighashes,
    )
    .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Verify adaptor signatures for a number of CETs
#[pyfunction]
pub fn verify_cet_adaptor_sigs(
    num_digits: u8,
    num_cets: u64,
    digit_string_template: String,
    oracle_pubkey: String,
    signing_pubkey: String,
    nonces: String,
    interval_wildcards: String,
    sighashes: String,
    signatures: String,
) -> PyResult<bool> {
    dlccryptlib::verify_cet_adaptor_sigs(
        num_digits,
        num_cets,
        &digit_string_template,
        &oracle_pubkey,
        &signing_pubkey,
        &nonces,
        &interval_wildcards,
        &sighashes,
        &signatures,
    )
    .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Perform final signing of a CET
#[pyfunction]
pub fn create_final_cet_sigs(
    signing_key_index4: u32,
    signing_key_index5: u32,
    signing_pubkey: String,
    other_pubkey: String,
    num_digits: u8,
    oracle_signatures: String,
    cet_value_wildcard: String,
    cet_sighash: String,
    other_adaptor_signature: String,
) -> PyResult<String> {
    dlccryptlib::create_final_cet_sigs(
        signing_key_index4,
        signing_key_index5,
        &signing_pubkey,
        &other_pubkey,
        num_digits,
        &oracle_signatures,
        &cet_value_wildcard,
        &cet_sighash,
        &other_adaptor_signature,
    )
    .map_err(|e| PyErr::new::<PyException, _>(e))
}

/// Perform final signing of a CET, decrypt a signature when outcome signatures are available.
/// Return the decrypted signature.
#[pyfunction]
pub fn create_final_cet_sig(
    pubkey: String,
    num_digits: u8,
    oracle_signatures: String,
    cet_value_wildcard: String,
    cet_sighash: String,
    adaptor_signature: String,
) -> PyResult<String> {
    dlccryptlib::create_final_cet_sig(
        &pubkey,
        num_digits,
        &oracle_signatures,
        &cet_value_wildcard,
        &cet_sighash,
        &adaptor_signature,
    )
    .map_err(|e| PyErr::new::<PyException, _>(e))
}

#[pymodule]
fn dlccryptlib_py(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init, m)?)?;
    m.add_function(wrap_pyfunction!(reinit_for_testing, m)?)?;
    m.add_function(wrap_pyfunction!(init_with_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(get_xpub, m)?)?;
    m.add_function(wrap_pyfunction!(get_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(get_address, m)?)?;
    m.add_function(wrap_pyfunction!(verify_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(sign_hash_ecdsa, m)?)?;
    m.add_function(wrap_pyfunction!(create_deterministic_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(sign_schnorr_with_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(verify_schnorr, m)?)?;
    m.add_function(wrap_pyfunction!(combine_pubkeys, m)?)?;
    m.add_function(wrap_pyfunction!(combine_seckeys, m)?)?;
    m.add_function(wrap_pyfunction!(create_cet_adaptor_sigs, m)?)?;
    m.add_function(wrap_pyfunction!(verify_cet_adaptor_sigs, m)?)?;
    m.add_function(wrap_pyfunction!(create_final_cet_sigs, m)?)?;
    m.add_function(wrap_pyfunction!(create_final_cet_sig, m)?)?;
    Ok(())
}
