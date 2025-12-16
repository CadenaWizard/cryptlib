# cryptlib -- DLC helper library

This library provides methods for working with Dicreet Log Contracts -- DLC's -- with adaptor signatures, on the Bitcoin chain.

This library is part of the Cadena Bitcoin platform, and used in places where DLC signatures are required (the Oracle server, the client application).

The [secp256k1_zkp](https://docs.rs/secp256k1-zkp/latest/secp256k1_zkp/) library is used for the cryptographic primitives -- this is the most complete and secure adaptor signatures implementation available.

The library is written in Rust (a programming environment popular for crypto implemetations, due to its correctness and performance aspects), but interfacing from Python or a C interface is also possible.


## Functionality

- Load and store seed phrase
- Generate child account keys, addresses
- Sign a hash using a child key
- Generate nonce values
- Perform Schnorr signature of a message using a given nonce, using a child key
- Create CET adaptor signature points (batch)
- Create final CET signature


## Roadmap

Currently `cryptlib` lives in two copies (with slight differences):

- Lib, this repo: https://github.com/CadenaWizard/cryptlib

- Client app: https://github.com/CadenaWizard/signer_app/tree/main/flutter_plugin

In the Oracle it is used from here, with a light Python wrapper. https://github.com/CadenaWizard/oracle/tree/main/dlcplazacryptlib

We plan to unify them into this repository.


## Developing

To build and test in Rust:

```
cargo build && cargo test
```

