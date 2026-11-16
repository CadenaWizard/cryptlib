# Copyright (c) 2025-present Cadena Bitcoin
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import dlccryptlib_py

xpub = dlccryptlib_py.init('sample_secret.sec', 'password')
print('Library initialized, xpub', xpub)

xpub = dlccryptlib_py.get_xpub()
print('Xpub', xpub)
pubkey0 = dlccryptlib_py.get_public_key(0, 0)
print('Pubkey 0', pubkey0)
address0 = dlccryptlib_py.get_address(0, 0)
print('Address 0', address0)

event_id = "event001"
# Fixed nonce values, for testing only. A real nonce comes from create_nonce and must never be reused.
nonce0_pub = "03ff8bb21842afb52a2e5d1f6f641b769b1cbf2344548184b2eac9dec426d87aeb"
print('Nonce 0 (pub)', nonce0_pub)
nonce1_sec = "a3bc5c98f60eee22a4b837812a528bf7e38c5bec43fe5ed39913e9cf8137b88d"
nonce1_pub = "027d1d1ba0982c4f81b22b56b3fe5099706c7fc9a080db31ec4bd8bfcb7d8cb3af"
print('Nonce 1 (pub)', nonce1_pub)
nonce2_sec = "c8473a73c5b617ed7adad27139e4e512cf6cb154722892ab9aecd7c497029fcd"

# Sign the event id with nonce1
sig = dlccryptlib_py.sign_schnorr_with_nonce(event_id, nonce1_sec, 0, 0)
print('Signature:  ', sig)

# Sign again (same nonce)
print('Sign again: ', dlccryptlib_py.sign_schnorr_with_nonce(event_id, nonce1_sec, 0, 0))

# Sign with different nonce
print('Sign with other nonce: ', dlccryptlib_py.sign_schnorr_with_nonce(event_id, nonce2_sec, 0, 0))

# Derived nonces: deterministic, from the master secret, the Oracle pubkey, the event ID and the digit index.
# The secret nonces never leave the library.
event_id = "btcusd1741474920"
template = "Outcome:btcusd1741474920:{digit_index}:{digit_outcome}"
nonces = dlccryptlib_py.create_derived_nonces(0, 0, pubkey0, event_id, 4)
print('Derived nonces', nonces)
assert len(nonces.split(" ")) == 4
assert dlccryptlib_py.create_derived_nonces(0, 0, pubkey0, event_id, 4) == nonces
assert dlccryptlib_py.verify_derived_nonces(0, 0, pubkey0, event_id, 4, nonces)
assert not dlccryptlib_py.verify_derived_nonces(0, 0, pubkey0, "other_event", 4, nonces)

# Attest the value 9534. An event must be attested only once: signing another outcome for it reveals the Oracle key.
attestation = dlccryptlib_py.sign_attestation_with_derived_nonces(0, 0, pubkey0, event_id, 4, template, "9534", nonces)
print('Attestation', attestation)
sigs = attestation.split(" ")
assert len(sigs) == 4
assert dlccryptlib_py.verify_schnorr("Outcome:btcusd1741474920:0:9", sigs[0], 0, 0)

# Wrong index for the pubkey: error
try:
    dlccryptlib_py.create_derived_nonces(0, 1, pubkey0, event_id, 4)
    assert False, "Expected an error"
except Exception as e:
    print('Expected error:', e)
