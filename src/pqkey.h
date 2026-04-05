// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: Hybrid ECDSA + ML-DSA-44 Key Classes

#ifndef RAVEN_PQKEY_H
#define RAVEN_PQKEY_H

#include "key.h"
#include "pubkey.h"
#include "crypto/mldsa.h"
#include "uint256.h"
#include "support/allocators/secure.h"

#include <vector>

/** Hybrid public key type byte */
static const unsigned char HYBRID_KEY_TYPE_MLDSA44 = 0x04;

/**
 * A hybrid post-quantum public key combining ECDSA/secp256k1 and ML-DSA-44.
 *
 * Format: type(1) || ecdsa_compressed_pubkey(33) || mldsa44_pubkey(1312) = 1346 bytes
 *
 * The witness program for a PQ address is: SHA256(hybrid_pubkey)
 */
class CHybridPubKey
{
public:
    static const size_t HYBRID_PUBKEY_SIZE = 1 + 33 + mldsa::PUBLICKEY_BYTES; // 1346

private:
    unsigned char vch[HYBRID_PUBKEY_SIZE];
    bool fValid;

public:
    CHybridPubKey() : fValid(false)
    {
        memset(vch, 0, sizeof(vch));
    }

    /** Construct from ECDSA and ML-DSA public keys */
    CHybridPubKey(const CPubKey& ecdsaPub, const unsigned char* mldsaPub)
    {
        Set(ecdsaPub, mldsaPub);
    }

    /** Set from component keys */
    void Set(const CPubKey& ecdsaPub, const unsigned char* mldsaPub)
    {
        if (!ecdsaPub.IsCompressed() || !mldsaPub) {
            fValid = false;
            return;
        }

        vch[0] = HYBRID_KEY_TYPE_MLDSA44;
        memcpy(vch + 1, ecdsaPub.begin(), 33);
        memcpy(vch + 34, mldsaPub, mldsa::PUBLICKEY_BYTES);
        fValid = true;
    }

    bool IsValid() const { return fValid; }

    /** Get the ECDSA component */
    CPubKey GetECDSAPubKey() const
    {
        return CPubKey(vch + 1, vch + 34);
    }

    /** Get pointer to the ML-DSA-44 public key component */
    const unsigned char* GetMLDSAPubKey() const
    {
        return vch + 34;
    }

    /** Get the type byte */
    unsigned char GetType() const { return vch[0]; }

    /** Raw data access */
    const unsigned char* data() const { return vch; }
    size_t size() const { return HYBRID_PUBKEY_SIZE; }

    /** Compute SHA256 hash for witness program (32 bytes) */
    uint256 GetWitnessProgram() const;

    /**
     * Verify a hybrid signature (ECDSA + ML-DSA) against a message hash.
     *
     * @param hash       Transaction sighash (32 bytes)
     * @param ecdsa_sig  ECDSA DER signature
     * @param mldsa_sig  ML-DSA-44 signature (2420 bytes)
     * @return true only if BOTH signatures are valid
     */
    bool Verify(const uint256& hash,
                const std::vector<unsigned char>& ecdsa_sig,
                const std::vector<unsigned char>& mldsa_sig) const;

    /** Serialize to a byte vector */
    std::vector<unsigned char> Serialize() const
    {
        return std::vector<unsigned char>(vch, vch + HYBRID_PUBKEY_SIZE);
    }

    /** Deserialize from raw bytes */
    bool Deserialize(const unsigned char* data, size_t len)
    {
        if (len != HYBRID_PUBKEY_SIZE || data[0] != HYBRID_KEY_TYPE_MLDSA44) {
            fValid = false;
            return false;
        }
        memcpy(vch, data, HYBRID_PUBKEY_SIZE);
        fValid = true;
        return true;
    }
};

/**
 * A hybrid private key combining ECDSA/secp256k1 and ML-DSA-44.
 *
 * Manages both key types and produces hybrid signatures where
 * both ECDSA and ML-DSA must verify (AND-composition).
 */
class CHybridKey
{
private:
    CKey ecdsaKey;
    std::vector<unsigned char, secure_allocator<unsigned char>> mldsaSK; // 2560 bytes
    std::vector<unsigned char> mldsaPK; // 1312 bytes
    bool fValid;

public:
    CHybridKey() : fValid(false)
    {
        mldsaSK.resize(mldsa::SECRETKEY_BYTES, 0);
        mldsaPK.resize(mldsa::PUBLICKEY_BYTES, 0);
    }

    ~CHybridKey()
    {
        // Secure cleanup
        if (mldsaSK.size() > 0)
            memset(mldsaSK.data(), 0, mldsaSK.size());
    }

    bool IsValid() const { return fValid; }

    /**
     * Generate a new hybrid keypair from a master seed.
     * Uses domain-separated derivation for independence:
     *   ECDSA:  HMAC-SHA512("ecdsa-secp256k1", seed)[0:32]
     *   ML-DSA: HMAC-SHA512("ml-dsa-44-rvn", seed)[0:32] -> ML-DSA keygen
     */
    bool MakeNewKey(const unsigned char* masterSeed = nullptr);

    /**
     * Sign a transaction hash with both ECDSA and ML-DSA.
     *
     * @param hash       Transaction sighash (32 bytes)
     * @param ecdsa_sig  Output: ECDSA DER signature
     * @param mldsa_sig  Output: ML-DSA-44 signature (2420 bytes)
     * @return true on success
     */
    bool Sign(const uint256& hash,
              std::vector<unsigned char>& ecdsa_sig,
              std::vector<unsigned char>& mldsa_sig) const;

    /** Get the hybrid public key */
    CHybridPubKey GetPubKey() const;

    /** Get the ECDSA component key (for legacy compatibility) */
    const CKey& GetECDSAKey() const { return ecdsaKey; }
};

#endif // RAVEN_PQKEY_H
