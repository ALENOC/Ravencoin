// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: ML-DSA-44 Post-Quantum Key Classes
//
// Witness v2 uses ML-DSA-44 signatures only (no ECDSA).
// Old addresses keep using ECDSA (witness v0).
// New PQ addresses use ML-DSA-44 exclusively.
// Gradual wallet migration makes the system quantum-resistant.

#ifndef RAVEN_PQKEY_H
#define RAVEN_PQKEY_H

#include "crypto/mldsa.h"
#include "serialize.h"
#include "uint256.h"
#include "support/allocators/secure.h"

#include <vector>

/** ML-DSA-44 public key used by RIP-25 witness v2. */
class CPQPubKey
{
private:
    std::vector<unsigned char> vch;

public:
    CPQPubKey() : vch() {}
    CPQPubKey(const unsigned char* pbegin, const unsigned char* pend) : vch(pbegin, pend) {}
    CPQPubKey(const std::vector<unsigned char>& v) : vch(v) {}

    unsigned int size() const { return vch.size(); }
    const unsigned char* data() const { return vch.data(); }
    const unsigned char* begin() const { return vch.data(); }
    const unsigned char* end() const { return vch.data() + vch.size(); }

    bool IsValid() const { return vch.size() == mldsa::PUBLICKEY_BYTES; }
    uint256 GetWitnessProgram() const;
    bool Verify(const uint256& hash, const std::vector<unsigned char>& sig) const;
    std::vector<unsigned char> GetVch() const { return vch; }

    friend bool operator==(const CPQPubKey& a, const CPQPubKey& b) { return a.vch == b.vch; }
    friend bool operator!=(const CPQPubKey& a, const CPQPubKey& b) { return a.vch != b.vch; }
    friend bool operator<(const CPQPubKey& a, const CPQPubKey& b) { return a.vch < b.vch; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(vch);
    }
};

/** ML-DSA-44 private key for post-quantum signing. */
class CPQKey
{
private:
    bool fValid;
    std::vector<unsigned char, secure_allocator<unsigned char>> keydata;
    CPQPubKey pubkey;

public:
    CPQKey() : fValid(false), keydata(mldsa::SECRETKEY_BYTES, 0) {}

    ~CPQKey()
    {
        if (!keydata.empty())
            memory_cleanse(keydata.data(), keydata.size());
    }

    bool IsValid() const { return fValid; }
    void MakeNewKey();

    /** Reserved for deterministic keygen; fails closed with pinned liboqs 0.12.0. */
    bool SetSeed(const unsigned char* seed);

    CPQPubKey GetPubKey() const { return pubkey; }
    bool Sign(const uint256& hash, std::vector<unsigned char>& sigOut) const;

    const std::vector<unsigned char, secure_allocator<unsigned char>>& GetKeyData() const { return keydata; }

    /** Restore secret-key bytes. The persisted public key must be rebound separately. */
    bool SetKeyData(const std::vector<unsigned char>& data);

    /** Bind the persisted public key after wallet deserialization/decryption. */
    bool SetPubKey(const CPQPubKey& pubkeyIn);
};

#endif // RAVEN_PQKEY_H
