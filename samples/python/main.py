import dlccryptlib_py

def sample():
    print("Dlccryptlib sample app, Python")

    entropy_hex = "00000000000000000000000000000001" # abandon x 11 actual
    network = "signet";

    xpub = dlccryptlib_py.init_with_entropy(entropy_hex, network)
    print(f"Library initialized, xpub {xpub}")

    pubkey0 = dlccryptlib_py.get_public_key(0, 0)
    print(f"pubkey 0: {pubkey0}")

    hash = "0001020300000000000000000000000000000000000000000000000000010203"
    sig = dlccryptlib_py.sign_hash_ecdsa(hash, 0, 0, pubkey0)
    print(f"signature: {sig}")

if __name__ == "__main__":
    sample()

