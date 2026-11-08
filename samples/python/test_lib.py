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
