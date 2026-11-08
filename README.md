# cryptlib -- DLC helper library

This library provides methods for working with Discreet Log Contracts -- DLCs -- with adaptor signatures, on the Bitcoin chain.

See [MODEL.md](MODEL.md) for the use case this library supports (actors, protocol steps, and the cryptography behind them).

This library is part of the Cadena Bitcoin platform, and used in places where DLC signatures are required (the Oracle server, the client application).

The [secp256k1_zkp](https://docs.rs/secp256k1-zkp/latest/secp256k1_zkp/) library is used for the cryptographic primitives -- this is the most complete and secure adaptor signatures implementation available.

The library is written in Rust (a programming environment popular for crypto implementations, due to its correctness and performance aspects), but interfacing from Python or a C interface is also possible.


## Functionality

- Initialize from a secret seed: either load it from an encrypted file, or pass the entropy directly
- Get the account XPUB; get child public keys and addresses; verify that a public key belongs to a child key
- Sign a hash (ECDSA) using a child key
- Generate unpredictable nonce values for an event and digit index
- Perform Schnorr signature of a message using a given nonce, using a child key; verify a Schnorr signature
- Combine (add) public keys or secret keys
- Create CET adaptor signatures (batch)
- Verify CET adaptor signatures (batch)
- Create final CET signatures from the Oracle's attestation: decrypt the counterparty's adaptor signature and add our own signature, or only decrypt

All functions are available from Rust and Python. The C interface covers a subset (initialization with entropy, XPUB, public key, address, hash signing, nonce generation, CET adaptor signature creation).


## Developing

Minimum supported Rust version (MSRV): **1.85**.

To build and test in Rust:

```
cargo build && cargo test
```

Publish the library:

```
cargo publish
```

To build the Python-wrapper library:

```
cd lib-py
./venv/bin/pip install -r requirements.txt
VIRTUAL_ENV="./venv" ./venv/bin/maturin develop
```

## Samples

```
cd samples/rust && cargo run && cd ../..
```

