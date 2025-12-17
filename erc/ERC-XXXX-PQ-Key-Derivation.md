erc: XXXX

title: Post-Quantum Key Derivation from BIP39 Seed

description: Standard derivation paths for post-quantum signature schemes from BIP39 mnemonics

author: ZKNOX Team (@zknox)

discussions-to: tbd

status: Draft

type: Standards Track

category: ERC

created: 2025-01-XX

requires: 4337


## Abstract

This ERC defines a standard method for deriving post-quantum (PQ) cryptographic keys from existing BIP39 mnemonics using BIP32 hierarchical deterministic derivation. The specification enables users to derive keys for multiple PQ signature schemes—including ML-DSA (Dilithium), Falcon, and hash-based signatures (XMSS)—from the same seed phrase used for their legacy secp256k1 Ethereum accounts. This provides a seamless migration path to quantum-resistant security without requiring users to manage additional secret material.

## Motivation

The advent of cryptographically relevant quantum computers (CRQCs) poses an existential threat to Ethereum's security model. The secp256k1 elliptic curve used for EOA signatures is vulnerable to Shor's algorithm, which can efficiently solve the discrete logarithm problem. When sufficiently powerful quantum computers become available:

1. **Any EOA that has ever sent a transaction** has its public key exposed on-chain, making its private key recoverable by a quantum attacker.
2. **Validator BLS signatures** (BLS12-381) are similarly vulnerable.
3. **Smart contract signature verification** using `ecrecover` becomes insecure.

The Ethereum community is actively developing post-quantum migration strategies, including:
- PQ signature verification precompiles
- STARK/WHIR-based signature aggregation
- ERC-4337 smart accounts with PQ verification

However, a critical gap exists: **there is no standard for how users should derive their PQ keys**. Without standardization:
- Wallet vendors will implement incompatible derivation schemes
- Users may lose access to funds if they switch wallets
- Recovery and migration tools cannot interoperate
- Hardware wallet support becomes fragmented

This ERC addresses this gap by specifying standard derivation paths that:
- Leverage the existing BIP39/BIP32 infrastructure
- Enable deterministic derivation of PQ keys from the same mnemonic
- Maintain backward compatibility with legacy key derivation
- Support multiple PQ algorithms to accommodate evolving standards

### Why Same-Seed Derivation Matters

The key insight is that **users already have secure seed phrases**. The BIP39 standard is:
- Well-understood and battle-tested
- Already backed up by millions of users
- Supported by all major hardware and software wallets

Requiring users to generate and secure a separate PQ seed would:
- Double the backup burden
- Increase the risk of seed loss
- Create confusion about which seed controls which assets

By deriving PQ keys from the existing seed, we ensure:
- **Zero additional backup required** — users keep their current seed phrase
- **Atomic migration** — the same seed controls both legacy and PQ keys
- **ZK recovery compatibility** — enables Vitalik's proposed ZK-based recovery mechanism for frozen EOAs

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 and RFC 8174.

### Overview

```
┌─────────────────────────────────────────────────────────────┐
│  BIP39 Mnemonic (12-24 words)                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  PBKDF2-HMAC-SHA512 (2048 rounds)                           │
│  Salt: "mnemonic" + passphrase                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  Master Seed (512 bits)                                     │
└─────────────────────────────────────────────────────────────┘
                              │
       ┌──────────┬───────────┼───────────┬──────────┐
       ▼          ▼           ▼           ▼          ▼
  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
  │ BIP32   │ │ BIP32   │ │ BIP32   │ │ BIP32   │ │ BIP32   │
  │ Legacy  │ │ r1      │ │ Falcon  │ │ ML-DSA  │ │ XMSS    │
  │ Path    │ │ Path    │ │ Path    │ │ Path    │ │ Path    │
  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
       │          │           │           │          │
       ▼          ▼           ▼           ▼          ▼
  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
  │secp256k1│ │secp256r1│ │ Falcon  │ │ ML-DSA  │ │ XMSS    │
  │Private  │ │Private  │ │ Seed    │ │ Seed    │ │ Seed    │
  │Key      │ │Key      │ │ (256b)  │ │ (256b)  │ │ (256b)  │
  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
```

### Derivation Paths

This ERC reserves the following `coin_type` values under BIP-44 for PQ algorithms:

| Algorithm | Coin Type | Full Path | Description |
|-----------|-----------|-----------|-------------|
| secp256k1 | 60 | `m/44'/60'/account'/change/index` | Legacy Ethereum (existing) |
| secp256r1 | 9001 | `m/44'/9001'/account'/change/index` | P-256 (EIP-7212) |
| Falcon-512 | 9002 | `m/44'/9002'/account'/change/index` | NIST PQC, lattice-based |
| ML-DSA-44 | 9003 | `m/44'/9003'/account'/change/index` | FIPS 204 Level 2 |
| XMSS-Poseidon | 9004 | `m/44'/9004'/account'/change/index` | Hash-based, ZK-friendly |
| SLH-DSA | 9005 | `m/44'/9005'/account'/change/index` | FIPS 205 (SPHINCS+) |
| Falcon-1024 | 9006 | `m/44'/9006'/account'/change/index` | NIST PQC, higher security |
| ML-DSA-65 | 9007 | `m/44'/9007'/account'/change/index` | FIPS 204 Level 3 |
| ML-DSA-87 | 9008 | `m/44'/9008'/account'/change/index` | FIPS 204 Level 5 |

The coin types 9001-9099 are reserved for cryptographic algorithm extensions under this specification.

### Path Components

Following BIP-44:

```
m / purpose' / coin_type' / account' / change / address_index
```

Where:
- `purpose` = 44 (BIP-44 compliant)
- `coin_type` = algorithm identifier (see table above)
- `account` = account index, starting at 0
- `change` = 0 for external (receiving), 1 for internal (change)
- `address_index` = address index, starting at 0

All components marked with `'` use hardened derivation.

### Seed Derivation Process

#### Step 1: BIP39 Mnemonic to Master Seed

The master seed SHALL be derived from the mnemonic using PBKDF2-HMAC-SHA512 as specified in BIP39:

```
master_seed = PBKDF2(
    password = mnemonic_sentence,
    salt = "mnemonic" + passphrase,
    iterations = 2048,
    key_length = 64,
    hash = SHA512
)
```

#### Step 2: BIP32 Path Derivation

For each algorithm, derive a 256-bit seed using BIP32/SLIP-0010:

```
algorithm_seed = BIP32_Derive(master_seed, path).private_key
```

The output is a 32-byte (256-bit) value that serves as the seed for the algorithm-specific key generation.

#### Step 3: Algorithm-Specific Key Generation

The 256-bit derived seed SHALL be used as input to the deterministic key generation function of each algorithm:

##### secp256k1 / secp256r1

The derived seed is used directly as the private key scalar:

```
private_key = algorithm_seed  // 32 bytes
public_key = private_key × G  // curve generator point
```

##### Falcon-512

The derived seed is expanded and used for deterministic key generation:

```
(sk, pk) = falcon512_keygen_deterministic(algorithm_seed)
```

The keygen process:
1. Expand seed via SHAKE256 to generate randomness
2. Sample NTRU polynomials f, g with small coefficients
3. Compute h = g/f mod (x^512 + 1) via NTT
4. Generate Falcon tree for signing

##### ML-DSA (Dilithium)

Per FIPS 204 Section 6.1, the seed is used for deterministic key generation:

```
(sk, pk) = ML-DSA.KeyGen_internal(algorithm_seed)
```

The 32-byte seed is expanded via SHAKE256 to derive:
- ρ (public seed for matrix A)
- ρ' (seed for secret vectors)
- K (seed for signing)

##### SLH-DSA (SPHINCS+)

Per FIPS 205, deterministic key generation from seed:

```
(sk, pk) = SLH-DSA.KeyGen(algorithm_seed)
```

##### XMSS-Poseidon

Hash-based signature with Poseidon hash function for ZK-friendliness:

```
(sk, pk) = XMSS_Poseidon.KeyGen(algorithm_seed, height=10)
```

Note: XMSS is a stateful signature scheme. Implementations MUST track and persist the signature index to prevent key reuse.

### Account Binding

To enable a unified identity across algorithms, accounts at the same index SHOULD be considered linked:

```
Legacy EOA:     m/44'/60'/0'/0/0   → 0x1234...
Falcon-512:     m/44'/9002'/0'/0/0 → pk_falcon
ML-DSA-44:      m/44'/9003'/0'/0/0 → pk_mldsa
XMSS-Poseidon:  m/44'/9004'/0'/0/0 → pk_xmss
```

All keys are derived from the same seed and represent the same logical identity at account index 0.

### Signature Algorithm Selection

When multiple PQ algorithms are available, the following priority order is RECOMMENDED:

1. **ML-DSA-65** — NIST standard, balanced security/size
2. **Falcon-512** — Compact signatures, good for on-chain verification
3. **SLH-DSA** — Conservative choice, hash-based security
4. **XMSS-Poseidon** — When ZK-proof generation is required

## Rationale

### Why BIP-44 Coin Types?

Using the BIP-44 `coin_type` field provides:
- Clear separation between algorithm namespaces
- Compatibility with existing HD wallet infrastructure
- Prevention of key reuse across algorithms
- Familiar mental model for wallet developers

Alternative approaches considered:
- **New purpose field**: Rejected because it would require new wallet infrastructure
- **Subpath under coin_type 60**: Rejected due to collision risk with existing tools
- **Entirely new derivation scheme**: Rejected to maximize compatibility

### Why 256-bit Seeds for PQ Algorithms?

Although some PQ algorithms (e.g., Falcon) could use larger seeds, 256 bits provides:
- **NIST Level 5 equivalent entropy** against quantum attacks (Grover reduces to 128-bit security)
- **Compatibility** with BIP32 which outputs 256-bit private keys
- **Sufficient randomness** for all NIST PQC algorithms

### Stateful Signature Warning

XMSS is a stateful signature scheme where each signature index can only be used once. Reusing an index compromises security. Implementations MUST:
- Persist signature state reliably
- Implement state synchronization for multi-device scenarios
- Consider stateless alternatives (SLH-DSA) when state management is impractical

## Backwards Compatibility

This ERC is fully backwards compatible:

1. **Existing seeds work unchanged** — Legacy secp256k1 derivation at `m/44'/60'/...` is unaffected
2. **Existing wallets can upgrade** — No changes required to legacy functionality
3. **Progressive adoption** — Wallets can implement PQ paths incrementally

Wallets that do not implement this ERC will simply not derive PQ keys, but will continue to function normally for legacy operations.

## Test Vectors

### Test Mnemonic

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
```

Passphrase: (empty)

### Master Seed

```
408b285c123836004f4b8842c89324c1...
(64 bytes total)
```

### Derived Seeds

| Algorithm | Path | Seed (hex) |
|-----------|------|------------|
| secp256k1 | `m/44'/60'/0'/0/0` | `1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f` |
| secp256r1 | `m/44'/9001'/0'/0/0` | `68777d4bbcdb59a98fb981ce42cea30804a1d02742e2c8e1b6b1d595f0321b54` |
| Falcon-512 | `m/44'/9002'/0'/0/0` | `c6ca7dd2bf1e40b82026851a85e21b3898cfb9d7d15c13dee2819a3f406231e0` |
| ML-DSA-44 | `m/44'/9003'/0'/0/0` | `b2c95f97474e1e8dbb6a79c77e745285a21e299ee0d7f225a7533986d04a862e` |
| XMSS-Poseidon | `m/44'/9004'/0'/0/0` | `9255a980d33b5f01ab5edd0f36ae67b713bd83a11d197481bc61a33e6e9816a0` |

### Derived Ethereum Address (secp256k1)

```
0xf278cf59f82edcf871d630f28ecc8056f25c1cdb
```

## Reference Implementation

A reference implementation in JavaScript is provided:

```javascript
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';

const PATHS = {
    secp256k1: "m/44'/60'/0'/0/0",
    secp256r1: "m/44'/9001'/0'/0/0",
    falcon512: "m/44'/9002'/0'/0/0",
    mldsa44: "m/44'/9003'/0'/0/0",
    xmssPoseidon: "m/44'/9004'/0'/0/0",
    slhdsa: "m/44'/9005'/0'/0/0",
    falcon1024: "m/44'/9006'/0'/0/0",
    mldsa65: "m/44'/9007'/0'/0/0",
    mldsa87: "m/44'/9008'/0'/0/0"
};

function deriveSeeds(mnemonic, passphrase = '') {
    // Validate mnemonic
    if (!bip39.validateMnemonic(mnemonic, wordlist)) {
        throw new Error('Invalid mnemonic');
    }
    
    // BIP39: Mnemonic → Master Seed
    const masterSeed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
    const hdkey = HDKey.fromMasterSeed(masterSeed);
    
    // Derive seed for each algorithm
    const results = {};
    for (const [algo, path] of Object.entries(PATHS)) {
        const derived = hdkey.derive(path);
        results[algo] = {
            path,
            seed: Buffer.from(derived.privateKey).toString('hex')
        };
    }
    
    return results;
}
```

Full implementation available at: [github.com/zknox/erc-xxxx-reference](https://github.com/zknox/erc-xxxx-reference)

## Security Considerations

### Seed Entropy

The security of all derived keys depends on the entropy of the original mnemonic:
- **12-word mnemonic**: 128 bits of entropy → 64 bits post-quantum (Grover)
- **24-word mnemonic**: 256 bits of entropy → 128 bits post-quantum (Grover)

For post-quantum security, **24-word mnemonics are REQUIRED**.

### BIP32 Derivation Security

BIP32 uses HMAC-SHA512 for key derivation. SHA-512 is quantum-resistant (Grover reduces security by half), so the derivation chain itself is PQ-secure with 256-bit seeds.

### Key Separation

Each algorithm uses a distinct `coin_type`, ensuring:
- No key material is shared across algorithms
- Compromise of one algorithm doesn't affect others
- Side-channel attacks on one implementation don't leak information about others

### Hardened Derivation

All sensitive path components (purpose, coin_type, account) use hardened derivation, preventing:
- Public key derivation attacks
- Extended public key leakage compromising private keys

### Implementation Security

Implementations MUST:
- Use constant-time operations for all cryptographic computations
- Zeroize sensitive memory after use
- Protect against side-channel attacks (timing, power analysis)
- Validate all inputs before processing

### Quantum Timeline Considerations

This standard assumes:
- CRQCs capable of breaking secp256k1 do not yet exist
- Users have time to migrate before quantum attacks are practical
- The PQ algorithms specified here will remain secure

If quantum computing advances faster than expected, emergency measures (EOA freezing, ZK recovery) may be necessary. This ERC's derivation scheme is compatible with the ZK recovery mechanism proposed by Vitalik Buterin.

### Stateful Signature Risks

For XMSS-Poseidon:
- **Index reuse is catastrophic** — leaks private key
- Implementations MUST use persistent, atomic state updates
- Multi-device usage requires coordination protocol
- Consider SLH-DSA (stateless) when state management is impractical

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
