# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

`dlccryptlib`: a Rust library for DLCs (Discreet Log Contracts) with adaptor signatures on Bitcoin, part of the Cadena Bitcoin platform. It is used by the Oracle server (through the Python wrapper) and by the client application. It holds the keys and does the cryptography; building and broadcasting transactions happens outside it (the library takes sighashes as input).

## Read first

- [README.md](README.md): overview, functionality list, build instructions.
- [MODEL.md](MODEL.md): the use case (actors, protocol steps, multiple and numerical outcomes).
- [MODEL.md, Appendix A](MODEL.md#appendix-a-cryptography-details): the cryptography, with references to the functions that implement it.

## Layout

- [src/lib.rs](src/lib.rs): public API. Facade functions with string (hex) parameters and results, using a global library instance. The C interface (`*_c` functions) is at the end of this file.
- [src/lib_struct.rs](src/lib_struct.rs): the `Lib` struct behind the facade (keys, nonces, signing).
- [src/adaptor_signature.rs](src/adaptor_signature.rs): Schnorr with a given nonce, signature points, CET adaptor signatures, final CET signatures.
- [src/hd_wallet_storage.rs](src/hd_wallet_storage.rs), [src/secret_entropy_storage.rs](src/secret_entropy_storage.rs): seed loading and HD key derivation.
- [src/test_lib.rs](src/test_lib.rs): unit tests.
- [lib-py/](lib-py/): Python wrapper (pyo3, built with maturin).
- [samples/rust/](samples/rust/), [samples/python/](samples/python/): samples, also run as tests in CI.

## Build and test

```
cargo build && cargo test
cd samples/rust && cargo run && cargo test && cd ../..
```

The Python wrapper and Python tests: see [README.md](README.md#developing) and [.github/workflows/build_python.yml](.github/workflows/build_python.yml). CI uses Rust 1.85, so don't rely on newer language features.

Run `cargo fmt` before finishing a change.

## Conventions

- A new or changed public function goes into the facade in `lib.rs` **and** into the Python wrapper in `lib-py/src/`. Add a `_c` variant where the C interface needs it.
- Facade functions return `Result<String, String>`. Lists are passed as space-separated hex strings.
- Keep [README.md](README.md) (functionality list) and [MODEL.md](MODEL.md) in sync with behavior changes.
- Terms: what MODEL.md calls a digit *pattern* (e.g. `0096***`) is a *wildcard* in the code (`interval_wildcards`, `cet_value_wildcard`). The Oracle's *attestation* is `oracle_signatures` in the code.

## Cryptography cautions

- Don't change message formats, hashing, or derivation paths without being asked. Other components (the Oracle, the client app) depend on them.
- An Oracle nonce must never be reused, and the secret nonce must never be predictable.
- Don't log or print secret keys, secret nonces, or seed entropy.
