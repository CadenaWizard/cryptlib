# cryptlib -- DLC helper library

The project builds on DLC (Dicreet Log Contracts) with adaptor signatures,
and relevant operations are needed in several places: in the signer app, in the Oracle, etc.

The DLC operations are extracted into a separate helper library.
The [secp256k1_zkp](https://docs.rs/secp256k1-zkp/latest/secp256k1_zkp/) library is used for the cryptographic primitives;
this is the most complete and secure adaptor signatures implementation available .
As it's written in Rust (a programming environment popular for crypto implemetations, due to its correctness and performance aspects),
we also wrote the helper in Rust, with bindings for other languages.


## Roadmap

Currently `cryptlib` lives in two copies (with slight differences):

https://github.com/CadenaWizard/oracle/tree/main/dlcplazacryptlib

https://github.com/CadenaWizard/signer_app/tree/main/flutter_plugin

We plan to unify them and extract to this repository.


