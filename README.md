# ZKNOX Key Derivation Tool

Derives 256-bit seeds for multiple signature schemes from a single BIP39 mnemonic, following BIP32/SLIP-0010 derivation.

## Supported Algorithms

| Algorithm | Path | Usage |
|-----------|------|-------|
| **secp256k1** | `m/44'/60'/0'/0/0` | Legacy Ethereum EOA |
| **secp256r1** | `m/44'/9001'/0'/0/0` | P-256 curve (EIP-7951) |
| **Falcon-512** | `m/44'/9002'/0'/0/0` | Post-Quantum (lattice) |
| **ML-DSA-44** | `m/44'/9003'/0'/0/0` | Post-Quantum (FIPS 204) |
| **XMSS-Poseidon** | `m/44'/9004'/0'/0/0` | Post-Quantum (hash-based, ZK-friendly) |

## Installation

```bash
npm install
```

## Usage

### Interactive Mode
```bash
node derive-keys.js
```
You will be prompted to enter your 24-word mnemonic.

### CLI Mode (testing only!)
```bash
node derive-keys.js word1 word2 word3 ... word24
```

⚠️ **Warning**: Never pass real mnemonics via CLI in production — they will be stored in shell history!

## Configuration

Edit `config.json` to customize derivation paths:

```json
{
  "paths": {
    "legacy_k1": "m/44'/60'/0'/0/0",
    "secp256r1": "m/44'/9001'/0'/0/0",
    "falcon512": "m/44'/9002'/0'/0/0",
    "dilithium44": "m/44'/9003'/0'/0/0",
    "xmss_poseidon": "m/44'/9004'/0'/0/0"
  }
}
```

## Output

The tool outputs:
1. Human-readable derivation steps
2. JSON with all derived seeds

```json
{
  "legacy_k1": {
    "path": "m/44'/60'/0'/0/0",
    "seed": "1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f",
    "seedLength": 256,
    "ethAddress": "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb",
    "usage": "Direct use as secp256k1 private key"
  },
  "falcon512": {
    "path": "m/44'/9002'/0'/0/0",
    "seed": "c6ca7dd2bf1e40b82026851a85e21b3898cfb9d7d15c13dee2819a3f406231e0",
    "seedLength": 256,
    "usage": "Input to Falcon-512 deterministic keygen"
  }
  // ...
}
```

## How It Works

<img width="1301" height="1232" alt="image-0" src="https://github.com/user-attachments/assets/a02fa513-6592-4a5d-a1ef-c25a58f709f0" />


The RNG generation of the mnemonic is not in the scope of the repo.

## Security Notes

- **Run offline only** — This tool handles sensitive key material
- **Clear terminal history** after use
- **Never log seeds** to files or remote services
- **Hardware security** — In production, this derivation should happen inside a secure enclave (HSM, TEE, hardware wallet)

## Dependencies

- `@scure/bip39` — BIP39 mnemonic handling
- `@scure/bip32` — BIP32/SLIP-0010 derivation
- `@noble/curves` — Elliptic curve operations
- `@noble/hashes` — Keccak256 for ETH address derivation

All dependencies are from the audited `@noble` / `@scure` family by Paul Miller.

## Test Vector

Using the standard test mnemonic (24× "abandon" + "art"):

```
Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art

Results:
- legacy_k1:     1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f
- ETH Address:   0xf278cf59f82edcf871d630f28ecc8056f25c1cdb
- secp256r1:     68777d4bbcdb59a98fb981ce42cea30804a1d02742e2c8e1b6b1d595f0321b54
- falcon512:     c6ca7dd2bf1e40b82026851a85e21b3898cfb9d7d15c13dee2819a3f406231e0
- dilithium44:   b2c95f97474e1e8dbb6a79c77e745285a21e299ee0d7f225a7533986d04a862e
- xmss_poseidon: 9255a980d33b5f01ab5edd0f36ae67b713bd83a11d197481bc61a33e6e9816a0
```

## Why it matters

In one of his post, Vitalik described
[how to hard-fork to save most users’ funds in a quantum emergency](https://ethresear.ch/t/how-to-hard-fork-to-save-most-users-funds-in-a-quantum-emergency/18901)
Using this BIP39 derivation, it is possible to provide a ZK BIP39 proof to migrate frozen accounts (once a Quantum computer is detected), without leaking the mnemonic seed. ZKNOX future works includes developping the following circuit:

<img width="1219" height="936" alt="image-3" src="https://github.com/user-attachments/assets/897787e4-fa42-462a-af0c-77f270edc688" />



## License

MIT — ZKNOX
