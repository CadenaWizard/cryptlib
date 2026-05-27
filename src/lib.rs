// Copyright (c) 2025-present Cadena Bitcoin
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

mod adaptor_signature;
mod hd_wallet_storage;
pub mod lib_struct;
mod network;
mod parse;
mod secret_entropy_storage;
#[cfg(test)]
mod test_lib;

use crate::adaptor_signature::combine_pubkeys_wrapper;
use crate::lib_struct::{global_lib, Lib};
use crate::parse::{
    hash_from_hex, keypair_from_sec_key_hex, pubkey_from_hex, schnorr_sig_from_hex,
};
use crate::secret_entropy_storage::parse_entropy_hex;

use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::secp256k1::{PublicKey, SecretKey};
use secp256k1_zkp::schnorr::Signature as SchnorrSignature;
use secp256k1_zkp::EcdsaAdaptorSignature; // Import missing types
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::str::FromStr;

/// Initialize the library, load secret from encrypted file. Return the XPUB.
pub fn init(
    path_for_secret_file: &str,
    encryption_password: &str,
    allow_reinit: bool,
) -> Result<String, String> {
    global_lib().write().unwrap().init_from_secret_file(
        path_for_secret_file,
        encryption_password,
        allow_reinit,
    )?;
    let xpub = global_lib().read().unwrap().get_xpub()?;
    Ok(xpub.to_string())
}

/// Initialize the library, provide the secret as parameter. Return the XPUB.
// #[cfg(test)]
pub fn init_with_entropy(entropy: &str, network: &str) -> Result<String, String> {
    let entropy_bin = parse_entropy_hex(entropy)?;
    global_lib()
        .write()
        .unwrap()
        .init_with_entropy(&entropy_bin, network)?;
    let xpub = global_lib().read().unwrap().get_xpub()?;
    Ok(xpub.to_string())
}

pub fn get_xpub() -> Result<String, String> {
    let xpub = global_lib().read().unwrap().get_xpub()?;
    Ok(xpub.to_string())
}

pub fn get_public_key(index4: u32, index5: u32) -> Result<String, String> {
    let pubkey = global_lib()
        .read()
        .unwrap()
        .get_child_public_key(index4, index5)?;
    Ok(pubkey.to_string())
}

pub fn get_address(index4: u32, index5: u32) -> Result<String, String> {
    let address = global_lib().read().unwrap().get_address(index4, index5)?;
    Ok(address.to_string())
}

pub fn verify_public_key(index4: u32, index5: u32, pubkey_str: &str) -> Result<bool, String> {
    let pubkey =
        pubkey_from_hex(pubkey_str).map_err(|e| format!("Failed to parse pubkey {}", e))?;
    let verify_result = global_lib()
        .read()
        .unwrap()
        .verify_child_public_key(index4, index5, &pubkey)?;
    Ok(verify_result)
}

pub fn sign_hash_ecdsa(
    hash_str: &str,
    index4: u32,
    index5: u32,
    signer_pubkey_str: &str,
) -> Result<String, String> {
    let hash = <[u8; 32]>::from_hex(hash_str)
        .map_err(|e| format!("Failed to parse hash hex, {}", e.to_string()))?;
    let signer_pubkey = pubkey_from_hex(signer_pubkey_str)
        .map_err(|e| format!("Failed to parse signer pubkey {}", e))?;
    let sig =
        global_lib()
            .read()
            .unwrap()
            .sign_hash_ecdsa(&hash, index4, index5, &signer_pubkey)?;
    Ok(sig.to_lower_hex_string())
}

pub fn create_deterministic_nonce(event_id: &str, index: u32) -> Result<(String, String), String> {
    let (sk, pk) = global_lib()
        .read()
        .unwrap()
        .create_deterministic_nonce(event_id, index)?;
    Ok((sk, pk.to_string()))
}

// Schnorr signing with nonce
pub fn sign_schnorr_with_nonce(
    msg: &str,
    nonce_sec_hex: &str,
    index4: u32,
    index5: u32,
) -> Result<String, String> {
    let nonce_sec_bin = <[u8; 32]>::from_hex(&nonce_sec_hex)
        .map_err(|e| format!("Error in nonce hex string {}", e))?;
    let sig = global_lib().read().unwrap().sign_schnorr_with_nonce(
        msg,
        &nonce_sec_bin,
        index4,
        index5,
    )?;
    Ok(sig.to_string())
}

// Schnorr signature verification
pub fn verify_schnorr(
    msg: &str,
    signature_hex: &str,
    index4: u32,
    index5: u32,
) -> Result<bool, String> {
    let signature = schnorr_sig_from_hex(signature_hex)
        .map_err(|e| format!("Error in signature hex string {}", e))?;
    let res = global_lib()
        .read()
        .unwrap()
        .verify_schnorr(msg, &signature, index4, index5)?;
    Ok(res)
}

pub fn combine_pubkeys(keys_hex: &str) -> Result<String, String> {
    let keys_split: Vec<_> = keys_hex.split(" ").collect();
    let mut keys = Vec::<PublicKey>::with_capacity(keys_split.len());
    for i in 0..keys_split.len() {
        let key_hex = keys_split[i].trim();
        if key_hex.len() > 0 {
            let key = pubkey_from_hex(&keys_split[i])
                .map_err(|e| format!("Failed to parse element {} {}", i, e))?;
            keys.push(key);
        }
    }
    let combined_key = combine_pubkeys_wrapper(keys.iter().collect::<Vec<_>>().as_slice())?;
    Ok(combined_key.to_string())
}

pub fn combine_seckeys(keys_hex: &str) -> Result<String, String> {
    let keys_split: Vec<_> = keys_hex.split(" ").collect();
    let mut keys = Vec::<SecretKey>::with_capacity(keys_split.len());
    for i in 0..keys_split.len() {
        let key_hex = keys_split[i].trim();
        if key_hex.len() > 0 {
            let keypair = keypair_from_sec_key_hex(&key_hex)
                .map_err(|e| format!("Failed to parse element {} {}", i, e))?;
            keys.push(keypair.secret_key());
        }
    }
    let combined_key = Lib::combine_seckeys(&keys)?;
    Ok(combined_key.display_secret().to_string())
}

pub fn create_cet_adaptor_sigs(
    num_digits: u8,
    num_cets: u64,
    digit_string_template: &str,
    oracle_pubkey_str: &str,
    signing_key_index4: u32,
    signing_key_index5: u32,
    signing_pubkey_str: &str,
    nonces: &str,
    interval_wildcards: &str,
    sighashes: &str,
) -> Result<String, String> {
    let nonces_split: Vec<_> = nonces.split(" ").collect();
    let mut nonces = Vec::<PublicKey>::with_capacity(nonces_split.len());
    for i in 0..nonces_split.len() {
        let key_hex = nonces_split[i].trim();
        if key_hex.len() > 0 {
            let pubkey = pubkey_from_hex(&key_hex)
                .map_err(|e| format!("Failed to parse element {} {}", i, e))?;
            nonces.push(pubkey);
        }
    }
    if nonces.len() != num_digits as usize {
        return Err(format!(
            "Wrong number of nonces {} {}",
            nonces.len(),
            num_digits
        ));
    }

    let wcs_split: Vec<_> = interval_wildcards.split(" ").collect();
    let mut wcs = Vec::<String>::with_capacity(wcs_split.len());
    for i in 0..wcs_split.len() {
        let wc = wcs_split[i].trim();
        if wc.len() > 0 {
            wcs.push(wc.to_owned());
        }
    }
    if wcs.len() != num_cets as usize {
        return Err(format!(
            "Wrong number of wildcards {} {}",
            wcs.len(),
            num_cets
        ));
    }

    let shs_split: Vec<_> = sighashes.split(" ").collect();
    let mut shs = Vec::<[u8; 32]>::with_capacity(shs_split.len());
    for i in 0..shs_split.len() {
        let sh = shs_split[i].trim();
        if sh.len() > 0 {
            let hash =
                hash_from_hex(&sh).map_err(|e| format!("Failed to parse element {} {}", i, e))?;
            shs.push(hash);
        }
    }
    if shs.len() != num_cets as usize {
        return Err(format!(
            "Wrong number of sighashes {} {}",
            shs.len(),
            num_cets
        ));
    }

    let oracle_pubkey = pubkey_from_hex(oracle_pubkey_str)
        .map_err(|e| format!("Failed to parse oracle pubkey {}", e))?;
    let signing_pubkey = pubkey_from_hex(signing_pubkey_str)
        .map_err(|e| format!("Failed to parse signing pubkey {}", e))?;

    let sigs = global_lib().read().unwrap().create_cet_adaptor_sigs(
        num_digits,
        num_cets,
        digit_string_template,
        &oracle_pubkey,
        signing_key_index4,
        signing_key_index5,
        &signing_pubkey,
        &nonces,
        &wcs,
        &shs,
    )?;

    let mut sigs_str = String::new();
    for s in sigs.iter() {
        sigs_str += &s.as_ref().to_lower_hex_string();
        sigs_str += " ";
    }

    Ok(sigs_str)
}

pub fn verify_cet_adaptor_sigs(
    num_digits: u8,
    num_cets: u64,
    digit_string_template: &str,
    oracle_pubkey_str: &str,
    signing_pubkey_str: &str,
    nonces: &str,
    interval_wildcards: &str,
    sighashes: &str,
    signatures: &str,
) -> Result<bool, String> {
    let nonces_split: Vec<_> = nonces.split(" ").collect();
    let mut nonces = Vec::<PublicKey>::with_capacity(nonces_split.len());
    for i in 0..nonces_split.len() {
        let key_hex = nonces_split[i].trim();
        if key_hex.len() > 0 {
            let pubkey = pubkey_from_hex(&key_hex)
                .map_err(|e| format!("Failed to parse element {} {}", i, e))?;
            nonces.push(pubkey);
        }
    }
    if nonces.len() != num_digits as usize {
        return Err(format!(
            "Wrong number of nonces {} {}",
            nonces.len(),
            num_digits
        ));
    }

    let wcs_split: Vec<_> = interval_wildcards.split(" ").collect();
    let mut wcs = Vec::<String>::with_capacity(wcs_split.len());
    for i in 0..wcs_split.len() {
        let wc = wcs_split[i].trim();
        if wc.len() > 0 {
            wcs.push(wc.to_owned());
        }
    }
    if wcs.len() != num_cets as usize {
        return Err(format!(
            "Wrong number of wildcards {} {}",
            wcs.len(),
            num_cets
        ));
    }

    let shs_split: Vec<_> = sighashes.split(" ").collect();
    let mut shs = Vec::<[u8; 32]>::with_capacity(shs_split.len());
    for i in 0..shs_split.len() {
        let sh = shs_split[i].trim();
        if sh.len() > 0 {
            let hash =
                hash_from_hex(&sh).map_err(|e| format!("Failed to parse element {} {}", i, e))?;
            shs.push(hash);
        }
    }
    if shs.len() != num_cets as usize {
        return Err(format!(
            "Wrong number of sighashes {} {}",
            shs.len(),
            num_cets
        ));
    }

    let sigs_split: Vec<_> = signatures.split(" ").collect();
    let mut sigs = Vec::<EcdsaAdaptorSignature>::with_capacity(sigs_split.len());
    for i in 0..sigs_split.len() {
        let sig = sigs_split[i].trim();
        if sig.len() > 0 {
            let s = EcdsaAdaptorSignature::from_str(sig)
                .map_err(|e| format!("Could not parse ECDSA adaptor signature {} {:?}", sig, e))?;
            sigs.push(s);
        }
    }
    if sigs.len() != num_cets as usize {
        return Err(format!(
            "Wrong number of signatures {} {}",
            sigs.len(),
            num_cets
        ));
    }

    let oracle_pubkey = pubkey_from_hex(oracle_pubkey_str)
        .map_err(|e| format!("Failed to parse oracle pubkey {}", e))?;
    let signing_pubkey = pubkey_from_hex(signing_pubkey_str)
        .map_err(|e| format!("Failed to parse signing pubkey {}", e))?;

    let res = global_lib().read().unwrap().verify_cet_adaptor_sigs(
        num_digits,
        num_cets,
        digit_string_template,
        &oracle_pubkey,
        &signing_pubkey,
        &nonces,
        &wcs,
        &shs,
        &sigs,
    );
    Ok(res.is_ok())
}

pub fn create_final_cet_sigs(
    signing_key_index4: u32,
    signing_key_index5: u32,
    signing_pubkey_str: &str,
    other_pubkey_str: &str,
    num_digits: u8,
    oracle_signatures_str: &str,
    cet_value_wildcard: &str,
    cet_sighash_str: &str,
    other_adaptor_signature_str: &str,
) -> Result<String, String> {
    let signing_pubkey = pubkey_from_hex(signing_pubkey_str)
        .map_err(|e| format!("Failed to parse signing pubkey {}", e))?;
    let other_pubkey = pubkey_from_hex(other_pubkey_str)
        .map_err(|e| format!("Failed to parse other pubkey {}", e))?;

    let sigs_split: Vec<_> = oracle_signatures_str.split(" ").collect();
    let mut sigs = Vec::<SchnorrSignature>::with_capacity(sigs_split.len());
    for i in 0..sigs_split.len() {
        let sig_hex = sigs_split[i].trim();
        if sig_hex.len() > 0 {
            let sig = schnorr_sig_from_hex(&sig_hex)
                .map_err(|e| format!("Failed to parse element {} {}", i, e))?;
            sigs.push(sig);
        }
    }
    if sigs.len() != num_digits as usize {
        return Err(format!(
            "Wrong number of signatures {} {}",
            sigs.len(),
            num_digits
        ));
    }

    let cet_sighash =
        hash_from_hex(cet_sighash_str).map_err(|e| format!("Failed to parse sighash {}", e))?;

    let other_adaptor_signature_bin = Vec::from_hex(other_adaptor_signature_str)
        .map_err(|e| format!("Failed to parse other adaptor sig {}", e))?;
    let other_adaptor_signature =
        EcdsaAdaptorSignature::from_slice(&other_adaptor_signature_bin)
            .map_err(|e| format!("Failed to parse other adaptor sig {}", e))?;
    let (sig1, sig2) = global_lib().read().unwrap().create_final_cet_sigs(
        signing_key_index4,
        signing_key_index5,
        &signing_pubkey,
        &other_pubkey,
        num_digits,
        &sigs,
        cet_value_wildcard,
        &cet_sighash,
        &other_adaptor_signature,
    )?;

    let sigs = format!(
        "{} {}",
        sig1.to_lower_hex_string(),
        sig2.to_lower_hex_string()
    );
    Ok(sigs)
}

pub fn create_final_cet_sig(
    pubkey_str: &str,
    num_digits: u8,
    oracle_signatures_str: &str,
    cet_value_wildcard: &str,
    cet_sighash_str: &str,
    adaptor_signature_str: &str,
) -> Result<String, String> {
    let pubkey =
        pubkey_from_hex(pubkey_str).map_err(|e| format!("Failed to parse other pubkey {}", e))?;

    let sigs_split: Vec<_> = oracle_signatures_str.split(" ").collect();
    let mut sigs = Vec::<SchnorrSignature>::with_capacity(sigs_split.len());
    for i in 0..sigs_split.len() {
        let sig_hex = sigs_split[i].trim();
        if sig_hex.len() > 0 {
            let sig = schnorr_sig_from_hex(&sig_hex)
                .map_err(|e| format!("Failed to parse element {} {}", i, e))?;
            sigs.push(sig);
        }
    }
    if sigs.len() != num_digits as usize {
        return Err(format!(
            "Wrong number of signatures {} {}",
            sigs.len(),
            num_digits
        ));
    }

    let cet_sighash =
        hash_from_hex(cet_sighash_str).map_err(|e| format!("Failed to parse sighash {}", e))?;

    let adaptor_signature_bin = Vec::from_hex(adaptor_signature_str)
        .map_err(|e| format!("Failed to parse adaptor sig {}", e))?;
    let adaptor_signature = EcdsaAdaptorSignature::from_slice(&adaptor_signature_bin)
        .map_err(|e| format!("Failed to parse adaptor sig {}", e))?;
    let sig = global_lib().read().unwrap().create_final_cet_sig(
        &pubkey,
        num_digits,
        &sigs,
        cet_value_wildcard,
        &cet_sighash,
        &adaptor_signature,
    )?;

    Ok(sig.to_lower_hex_string())
}

// ##### Facade functions for C-style-interface invocations

/// Initialize the library, provide the secret as parameter. Return the XPUB.
#[no_mangle]
pub extern "C" fn init_with_entropy_c(
    entropy: *const c_char,
    network: *const c_char,
) -> *mut c_char {
    // Convert input parameter from raw pointer to Rust string
    let entropy_str = unsafe {
        CStr::from_ptr(entropy)
            .to_str()
            .unwrap_or("Error in entropy parameter")
    };
    let network_str = unsafe {
        CStr::from_ptr(network)
            .to_str()
            .unwrap_or("Error in network parameter")
    };

    match init_with_entropy(entropy_str, network_str) {
        Ok(xpub) => {
            // Return as a C string
            CString::new(xpub).unwrap().into_raw()
        }
        Err(e) => error_as_cstr_prefix(e),
    }
}

/// Return a child public key (specified by its index).
#[no_mangle]
pub extern "C" fn get_public_key_c(index4: u32, index5: u32) -> *mut c_char {
    match get_public_key(index4, index5) {
        Ok(pubkey) => {
            // Return as a C string
            CString::new(pubkey).unwrap().into_raw()
        }
        Err(e) => error_as_cstr_prefix(e),
    }
}

/// Sign a hash with a child private key (specified by its index).
#[no_mangle]
pub extern "C" fn sign_hash_ecdsa_c(
    hash: *const c_char,
    signer_index4: u32,
    signer_index5: u32,
    signer_pubkey: *const c_char,
) -> *mut c_char {
    // Convert input parameter from raw pointer to Rust string
    let hash_str = unsafe {
        CStr::from_ptr(hash)
            .to_str()
            .unwrap_or("Error in hash parameter")
    };
    let signer_pubkey_str = unsafe {
        CStr::from_ptr(signer_pubkey)
            .to_str()
            .unwrap_or("Error in signer_pubkey parameter")
    };

    match sign_hash_ecdsa(hash_str, signer_index4, signer_index5, signer_pubkey_str) {
        Ok(sig) => {
            // Return as a C string
            CString::new(sig).unwrap().into_raw()
        }
        Err(e) => error_as_cstr_prefix(e),
    }
}

/// Create adaptor signatures for a number of CETs
#[no_mangle]
pub extern "C" fn create_cet_adaptor_sigs_c(
    num_digits: u8,
    num_cets: u32,
    digit_string_template: *const c_char,
    oracle_pubkey: *const c_char,
    signing_key_index4: u32,
    signing_key_index5: u32,
    signing_pubkey: *const c_char,
    nonces: *const c_char,
    interval_wildcards: *const c_char,
    sighashes: *const c_char,
) -> *mut c_char {
    // Convert input parameter from raw pointer to Rust string
    let digit_string_template_str = unsafe {
        CStr::from_ptr(digit_string_template)
            .to_str()
            .unwrap_or("Error in digit_string_template parameter")
    };
    let oracle_pubkey_str = unsafe {
        CStr::from_ptr(oracle_pubkey)
            .to_str()
            .unwrap_or("Error in oracle_pubkey parameter")
    };
    let signing_pubkey_str = unsafe {
        CStr::from_ptr(signing_pubkey)
            .to_str()
            .unwrap_or("Error in signing_pubkey parameter")
    };
    let nonces_str = unsafe {
        CStr::from_ptr(nonces)
            .to_str()
            .unwrap_or("Error in nonces parameter")
    };
    let interval_wildcards_str = unsafe {
        CStr::from_ptr(interval_wildcards)
            .to_str()
            .unwrap_or("Error in interval_wildcards parameter")
    };
    let sighashes_str = unsafe {
        CStr::from_ptr(sighashes)
            .to_str()
            .unwrap_or("Error in sighashes parameter")
    };

    match create_cet_adaptor_sigs(
        num_digits,
        num_cets as u64,
        digit_string_template_str,
        oracle_pubkey_str,
        signing_key_index4,
        signing_key_index5,
        signing_pubkey_str,
        nonces_str,
        interval_wildcards_str,
        sighashes_str,
    ) {
        Ok(sigs) => {
            // Return as a C string
            CString::new(sigs).unwrap().into_raw()
        }
        Err(e) => error_as_cstr_prefix(e),
    }
}

#[no_mangle]
pub extern "C" fn create_deterministic_nonce_c(event_id: *const c_char, index: u32) -> *mut c_char {
    // Convert the event_id from raw pointer to Rust string
    let event_id_str = unsafe {
        CStr::from_ptr(event_id)
            .to_str()
            .unwrap_or("Error in event ID")
    };

    // Call your existing function that creates the nonce (assuming this is what you want)
    match create_deterministic_nonce(event_id_str, index) {
        Ok((sk, pk)) => {
            // Return as a C string
            CString::new(format!("{} {}", sk, pk)).unwrap().into_raw()
        }
        Err(e) => error_as_cstr_prefix(e),
    }
}

#[no_mangle]
pub extern "C" fn get_xpub_c() -> *mut c_char {
    match get_xpub() {
        Ok(xpub) => CString::new(xpub).unwrap().into_raw(),
        Err(e) => error_as_cstr_prefix(e),
    }
}

#[no_mangle]
pub extern "C" fn get_address_c(index4: u32, index5: u32) -> *mut c_char {
    match get_address(index4, index5) {
        Ok(address) => CString::new(address).unwrap().into_raw(),
        Err(e) => error_as_cstr_prefix(e),
    }
}

#[no_mangle]
pub extern "C" fn free_cstring(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        let _ = CString::from_raw(s);
    }
}

// Return error with an "ERROR: " prefix, as a C string
fn error_as_cstr_prefix(error: String) -> *mut c_char {
    CString::new(format!("ERROR: {}", error))
        .unwrap()
        .into_raw()
}
