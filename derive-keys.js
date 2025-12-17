/**
 * ZKNOX Key Derivation Tool
 * 
 * Derives seeds for multiple signature schemes from a BIP39 mnemonic.
 * - Legacy secp256k1 (Ethereum EOA)
 * - secp256r1 (P-256, EIP-7212)
 * - Falcon-512 (PQ lattice-based)
 * - ML-DSA-44 / Dilithium (PQ lattice-based, FIPS 204)
 * - XMSS-Poseidon (PQ hash-based, ZK-friendly)
 * 
 * Usage: node derive-keys.js [mnemonic]
 * If no mnemonic provided, will prompt for input.
 */

import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { keccak_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createInterface } from 'readline';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ============================================
// Configuration Loading
// ============================================

function loadConfig() {
    const configPath = join(__dirname, 'config.json');
    try {
        const configData = readFileSync(configPath, 'utf8');
        return JSON.parse(configData);
    } catch (error) {
        console.error(`Error loading config.json: ${error.message}`);
        process.exit(1);
    }
}

// ============================================
// BIP39 / BIP32 Core Functions
// ============================================

/**
 * Convert mnemonic to 512-bit master seed
 * @param {string} mnemonic - 24 words space-separated
 * @param {string} passphrase - Optional BIP39 passphrase
 * @returns {Uint8Array} - 64 bytes (512 bits) master seed
 */
function mnemonicToSeed(mnemonic, passphrase = '') {
    // Validate mnemonic
    const words = mnemonic.trim().split(/\s+/);
    if (words.length !== 24 && words.length !== 12) {
        throw new Error(`Invalid mnemonic: expected 12 or 24 words, got ${words.length}`);
    }
    
    if (!bip39.validateMnemonic(mnemonic, wordlist)) {
        throw new Error('Invalid mnemonic: checksum failed or invalid words');
    }
    
    // PBKDF2-HMAC-SHA512, 2048 rounds
    return bip39.mnemonicToSeedSync(mnemonic, passphrase);
}

/**
 * Derive a child key from master seed using BIP32/SLIP-0010
 * @param {Uint8Array} masterSeed - 512-bit master seed
 * @param {string} path - Derivation path (e.g., "m/44'/60'/0'/0/0")
 * @returns {Uint8Array} - 32 bytes (256 bits) derived private key / seed
 */
function derivePath(masterSeed, path) {
    const hdkey = HDKey.fromMasterSeed(masterSeed);
    const derived = hdkey.derive(path);
    
    if (!derived.privateKey) {
        throw new Error(`Failed to derive key at path: ${path}`);
    }
    
    return derived.privateKey;
}

// ============================================
// Key Type Specific Functions
// ============================================

/**
 * Derive Ethereum address from secp256k1 private key
 */
function privateKeyToEthAddress(privateKey) {
    const publicKey = secp256k1.getPublicKey(privateKey, false); // Uncompressed
    const publicKeyWithoutPrefix = publicKey.slice(1); // Remove 0x04 prefix
    const hash = keccak_256(publicKeyWithoutPrefix);
    return '0x' + Buffer.from(hash.slice(-20)).toString('hex');
}

/**
 * Derive all keys from mnemonic
 */
function deriveAllKeys(mnemonic, config, passphrase = '') {
    console.log('\n🔐 ZKNOX Key Derivation Tool\n');
    console.log('='.repeat(60));
    
    // Step 1: Mnemonic to Master Seed
    console.log('\n📝 Step 1: BIP39 Mnemonic → Master Seed');
    const masterSeed = mnemonicToSeed(mnemonic, passphrase);
    console.log(`   Master Seed (512 bits): ${Buffer.from(masterSeed).toString('hex').slice(0, 32)}...`);
    
    const results = {};
    const paths = config.paths;
    
    console.log('\n🔀 Step 2: BIP32 Derivation for each algorithm\n');
    
    // ---- Legacy secp256k1 (Ethereum) ----
    console.log('─'.repeat(60));
    console.log('🔑 Legacy secp256k1 (Ethereum EOA)');
    console.log(`   Path: ${paths.legacy_k1}`);
    
    const k1Seed = derivePath(masterSeed, paths.legacy_k1);
    const ethAddress = privateKeyToEthAddress(k1Seed);
    
    results.legacy_k1 = {
        path: paths.legacy_k1,
        seed: Buffer.from(k1Seed).toString('hex'),
        seedLength: k1Seed.length * 8,
        ethAddress: ethAddress,
        usage: 'Direct use as secp256k1 private key'
    };
    
    console.log(`   Seed (256 bits): ${results.legacy_k1.seed}`);
    console.log(`   ETH Address: ${ethAddress}`);
    
    // ---- secp256r1 (P-256) ----
    console.log('\n' + '─'.repeat(60));
    console.log('🔑 secp256r1 (P-256 / EIP-7212)');
    console.log(`   Path: ${paths.secp256r1}`);
    
    const r1Seed = derivePath(masterSeed, paths.secp256r1);
    
    results.secp256r1 = {
        path: paths.secp256r1,
        seed: Buffer.from(r1Seed).toString('hex'),
        seedLength: r1Seed.length * 8,
        usage: 'Direct use as secp256r1 private key'
    };
    
    console.log(`   Seed (256 bits): ${results.secp256r1.seed}`);
    
    // ---- Falcon-512 ----
    console.log('\n' + '─'.repeat(60));
    console.log('🔑 Falcon-512 (Post-Quantum, Lattice/NTRU)');
    console.log(`   Path: ${paths.falcon512}`);
    
    const falconSeed = derivePath(masterSeed, paths.falcon512);
    
    results.falcon512 = {
        path: paths.falcon512,
        seed: Buffer.from(falconSeed).toString('hex'),
        seedLength: falconSeed.length * 8,
        usage: 'Input to Falcon-512 deterministic keygen',
        publicKeySize: '897 bytes',
        privateKeySize: '1281 bytes',
        signatureSize: '~666 bytes'
    };
    
    console.log(`   Seed (256 bits): ${results.falcon512.seed}`);
    console.log(`   → Feed to falcon512_keygen_deterministic(seed)`);
    
    // ---- ML-DSA-44 / Dilithium ----
    console.log('\n' + '─'.repeat(60));
    console.log('🔑 ML-DSA-44 / Dilithium (Post-Quantum, FIPS 204)');
    console.log(`   Path: ${paths.dilithium44}`);
    
    const dilithiumSeed = derivePath(masterSeed, paths.dilithium44);
    
    results.dilithium44 = {
        path: paths.dilithium44,
        seed: Buffer.from(dilithiumSeed).toString('hex'),
        seedLength: dilithiumSeed.length * 8,
        usage: 'Input to ML-DSA-44 deterministic keygen (FIPS 204 §6.1)',
        publicKeySize: '1312 bytes',
        privateKeySize: '2560 bytes',
        signatureSize: '2420 bytes',
        securityLevel: 'NIST Level 2 (~128 bits classical)'
    };
    
    console.log(`   Seed (256 bits): ${results.dilithium44.seed}`);
    console.log(`   → Feed to ml_dsa_44_keygen(seed) per FIPS 204`);
    
    // ---- XMSS-Poseidon ----
    console.log('\n' + '─'.repeat(60));
    console.log('🔑 XMSS-Poseidon (Post-Quantum, Hash-based, ZK-friendly)');
    console.log(`   Path: ${paths.xmss_poseidon}`);
    
    const xmssSeed = derivePath(masterSeed, paths.xmss_poseidon);
    
    results.xmss_poseidon = {
        path: paths.xmss_poseidon,
        seed: Buffer.from(xmssSeed).toString('hex'),
        seedLength: xmssSeed.length * 8,
        usage: 'Input to XMSS keygen with Poseidon hash',
        publicKeySize: '~64 bytes (Merkle root + params)',
        privateKeySize: 'TBD (depends on tree height)',
        signatureSize: 'TBD',
        note: 'Stateful signature scheme - track signature index!'
    };
    
    console.log(`   Seed (256 bits): ${results.xmss_poseidon.seed}`);
    console.log(`   → Feed to poseidon_xmss_keygen(seed)`);
    
    console.log('\n' + '='.repeat(60));
    console.log('✅ Derivation complete\n');
    
    return results;
}

// ============================================
// Input Handling
// ============================================

async function getMnemonicFromUser() {
    const rl = createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    return new Promise((resolve) => {
        console.log('\n🔐 ZKNOX Key Derivation Tool');
        console.log('Enter your 24-word mnemonic (space-separated):');
        console.log('⚠️  WARNING: Only use this tool in a secure, offline environment!\n');
        
        rl.question('Mnemonic: ', (answer) => {
            rl.close();
            resolve(answer.trim());
        });
    });
}

// ============================================
// Main Entry Point
// ============================================

async function main() {
    // Load configuration
    const config = loadConfig();
    
    // Get mnemonic from CLI argument or prompt
    let mnemonic;
    
    if (process.argv[2]) {
        // Mnemonic provided as argument (for testing only!)
        mnemonic = process.argv.slice(2).join(' ');
    } else {
        // Interactive input
        mnemonic = await getMnemonicFromUser();
    }
    
    if (!mnemonic) {
        console.error('Error: No mnemonic provided');
        process.exit(1);
    }
    
    try {
        // Derive all keys
        const results = deriveAllKeys(mnemonic, config);
        
        // Output JSON for programmatic use
        console.log('\n📋 JSON Output:\n');
        console.log(JSON.stringify(results, null, 2));
        
        // Security reminder
        console.log('\n' + '⚠️'.repeat(30));
        console.log('SECURITY REMINDER:');
        console.log('- Clear your terminal history');
        console.log('- Never share these seeds');
        console.log('- Store seeds in secure hardware');
        console.log('- This output should be used offline only');
        console.log('⚠️'.repeat(30) + '\n');
        
    } catch (error) {
        console.error(`\n❌ Error: ${error.message}\n`);
        process.exit(1);
    }
}

// Run
main().catch(console.error);
