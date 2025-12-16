import dlccryptlib

def sample():
    print("Dlccryptlib sample app, Python")

    entropy_hex = "99d33a674ce99d33a674ce99d33a674c" # oil x 12
    network = "signet";

    xpub = dlccryptlib.init_with_entropy(entropy_hex, network)
    print(f"Library initialized, xpub {xpub}")

    pubkey0 = dlccryptlib.get_public_key(0)
    print(f"pubkey 0: {pubkey0}")

    hash = "0001020300000000000000000000000000000000000000000000000000010203"
    sig = dlccryptlib.sign_hash_ecdsa(hash, 0, pubkey0)
    print(f"signature: {sig}")

if __name__ == "__main__":
    sample()

