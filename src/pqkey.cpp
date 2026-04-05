// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: Hybrid ECDSA + ML-DSA-44 Key Implementation

#include "pqkey.h"
#include "crypto/hmac_sha512.h"
#include "crypto/sha256.h"
#include "random.h"

#include <cstring>

// --- CHybridPubKey ---

uint256 CHybridPubKey::GetWitnessProgram() const
{
    uint256 result;
    CSHA256 hasher;
    hasher.Write(vch, HYBRID_PUBKEY_SIZE);
    hasher.Finalize(result.begin());
    return result;
}

bool CHybridPubKey::Verify(const uint256& hash,
                           const std::vector<unsigned char>& ecdsa_sig,
                           const std::vector<unsigned char>& mldsa_sig) const
{
    if (!fValid)
        return false;

    // 1. Verify ECDSA signature
    CPubKey ecdsaPub = GetECDSAPubKey();
    if (!ecdsaPub.Verify(hash, ecdsa_sig))
        return false;

    // 2. Verify ML-DSA-44 signature
    if (mldsa_sig.size() != mldsa::SIGNATURE_BYTES)
        return false;

    if (!mldsa::Verify(mldsa_sig.data(), mldsa_sig.size(),
                       hash.begin(), 32,
                       GetMLDSAPubKey()))
        return false;

    // Both valid: hybrid signature is valid
    return true;
}


// --- CHybridKey ---

bool CHybridKey::MakeNewKey(const unsigned char* masterSeed)
{
    unsigned char seed[32];

    if (masterSeed) {
        memcpy(seed, masterSeed, 32);
    } else {
        GetStrongRandBytes(seed, 32);
    }

    // Domain-separated key derivation from single master seed
    // This ensures ECDSA and ML-DSA keys are cryptographically independent

    // 1. Derive ECDSA private key
    unsigned char ecdsa_derived[64];
    CHMAC_SHA512 ecdsa_hmac((const unsigned char*)"ecdsa-secp256k1", 15);
    ecdsa_hmac.Write(seed, 32);
    ecdsa_hmac.Finalize(ecdsa_derived);

    // Use first 32 bytes as ECDSA private key
    ecdsaKey.Set(ecdsa_derived, ecdsa_derived + 32, true /* compressed */);
    if (!ecdsaKey.IsValid()) {
        memset(seed, 0, 32);
        memset(ecdsa_derived, 0, 64);
        fValid = false;
        return false;
    }

    // 2. Derive ML-DSA-44 seed (independent from ECDSA)
    unsigned char mldsa_seed[64];
    CHMAC_SHA512 mldsa_hmac((const unsigned char*)"ml-dsa-44-rvn", 13);
    mldsa_hmac.Write(seed, 32);
    mldsa_hmac.Finalize(mldsa_seed);

    // Generate ML-DSA-44 keypair from derived seed
    if (!mldsa::KeyGen(mldsaPK.data(), mldsaSK.data(), mldsa_seed)) {
        memset(seed, 0, 32);
        memset(ecdsa_derived, 0, 64);
        memset(mldsa_seed, 0, 64);
        fValid = false;
        return false;
    }

    // Secure cleanup of intermediate material
    memset(seed, 0, 32);
    memset(ecdsa_derived, 0, 64);
    memset(mldsa_seed, 0, 64);

    fValid = true;
    return true;
}

bool CHybridKey::Sign(const uint256& hash,
                      std::vector<unsigned char>& ecdsa_sig,
                      std::vector<unsigned char>& mldsa_sig) const
{
    if (!fValid)
        return false;

    // 1. ECDSA signature
    if (!ecdsaKey.Sign(hash, ecdsa_sig))
        return false;

    // 2. ML-DSA-44 signature
    mldsa_sig.resize(mldsa::SIGNATURE_BYTES);
    size_t siglen = 0;
    if (!mldsa::Sign(mldsa_sig.data(), &siglen,
                     hash.begin(), 32,
                     mldsaSK.data()))
        return false;

    if (siglen != mldsa::SIGNATURE_BYTES)
        return false;

    return true;
}

CHybridPubKey CHybridKey::GetPubKey() const
{
    CHybridPubKey result;
    if (fValid) {
        CPubKey ecdsaPub = ecdsaKey.GetPubKey();
        result.Set(ecdsaPub, mldsaPK.data());
    }
    return result;
}
