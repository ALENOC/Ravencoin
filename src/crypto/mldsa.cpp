// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: ML-DSA-44 Post-Quantum Signature Wrapper
//
// PROOF-OF-CONCEPT SIMULATION
// ============================
// This uses HMAC-SHA512 to simulate ML-DSA-44 with correct API and sizes.
// Production code will replace this with liboqs (FIPS 204 compliant).
//
// PoC signature scheme:
//   Sign(sk, msg):
//     seed = sk[0:32], pk_hash = sk[32:64]
//     sig_core = Expand(seed || pk_hash || msg, 2388 bytes)
//     binding  = HMAC(pk_hash, sig_core || msg)[0:32]
//     sig = sig_core || binding  (2420 bytes total)
//
//   Verify(pk, msg, sig):
//     pk_hash = SHA256(pk)
//     sig_core = sig[0:2388], binding = sig[2388:2420]
//     expected = HMAC(pk_hash, sig_core || msg)[0:32]
//     return binding == expected

#include "mldsa.h"
#include "hmac_sha512.h"
#include "sha256.h"

#include <cstring>

// For random keygen
extern void GetStrongRandBytes(unsigned char* buf, int num);

namespace mldsa {

// Deterministic expansion via HMAC-SHA512 chain
static void ExpandSeed(const unsigned char* input, size_t inputlen,
                       const char* domain, unsigned char* out, size_t outlen)
{
    size_t pos = 0;
    uint32_t counter = 0;

    while (pos < outlen) {
        CHMAC_SHA512 hmac(input, inputlen);
        hmac.Write((const unsigned char*)domain, strlen(domain));

        unsigned char ctr[4];
        ctr[0] = (counter >> 24) & 0xFF;
        ctr[1] = (counter >> 16) & 0xFF;
        ctr[2] = (counter >> 8) & 0xFF;
        ctr[3] = counter & 0xFF;
        hmac.Write(ctr, 4);

        unsigned char hash[64];
        hmac.Finalize(hash);

        size_t tocopy = (outlen - pos < 64) ? outlen - pos : 64;
        memcpy(out + pos, hash, tocopy);
        pos += tocopy;
        counter++;
    }
}

// Compute binding tag: HMAC(pk_hash, sig_core || msg || domain)[0:32]
static void ComputeBinding(const unsigned char* pk_hash,
                           const unsigned char* sig_core, size_t corelen,
                           const unsigned char* msg, size_t msglen,
                           unsigned char* binding)
{
    CHMAC_SHA512 hmac(pk_hash, 32);
    hmac.Write(sig_core, corelen);
    hmac.Write(msg, msglen);
    hmac.Write((const unsigned char*)"ml-dsa-44-bind-v1", 17);
    unsigned char full[64];
    hmac.Finalize(full);
    memcpy(binding, full, 32);
}

bool KeyGen(unsigned char* pk, unsigned char* sk, const unsigned char* seed)
{
    if (!pk || !sk || !seed)
        return false;

    // Derive public key from seed
    ExpandSeed(seed, SEED_BYTES, "ml-dsa-44-pk-v1", pk, PUBLICKEY_BYTES);

    // Build secret key: seed(32) || pk_hash(32) || expanded_sk(2496)
    // Store seed at beginning
    memcpy(sk, seed, SEED_BYTES);

    // Store SHA256(pk) at offset 32 for use during signing
    CSHA256 pkhasher;
    pkhasher.Write(pk, PUBLICKEY_BYTES);
    pkhasher.Finalize(sk + SEED_BYTES);

    // Fill remaining secret key material
    ExpandSeed(seed, SEED_BYTES, "ml-dsa-44-sk-expand-v1",
               sk + SEED_BYTES + 32, SECRETKEY_BYTES - SEED_BYTES - 32);

    return true;
}

bool KeyGenRandom(unsigned char* pk, unsigned char* sk)
{
    unsigned char seed[SEED_BYTES];
    GetStrongRandBytes(seed, SEED_BYTES);
    bool result = KeyGen(pk, sk, seed);
    memset(seed, 0, SEED_BYTES);
    return result;
}

bool Sign(unsigned char* sig, size_t* siglen,
          const unsigned char* msg, size_t msglen,
          const unsigned char* sk)
{
    if (!sig || !siglen || !msg || !sk)
        return false;

    const size_t CORE_BYTES = SIGNATURE_BYTES - 32; // 2388 bytes for core, 32 for binding

    // Extract components from secret key
    const unsigned char* seed = sk;           // sk[0:32]
    const unsigned char* pk_hash = sk + 32;   // sk[32:64] = SHA256(pk)

    // Build signing input: seed || pk_hash || msg
    std::vector<unsigned char> signing_input(SEED_BYTES + 32 + msglen);
    memcpy(signing_input.data(), seed, SEED_BYTES);
    memcpy(signing_input.data() + SEED_BYTES, pk_hash, 32);
    memcpy(signing_input.data() + SEED_BYTES + 32, msg, msglen);

    // Generate signature core (requires secret key knowledge)
    ExpandSeed(signing_input.data(), signing_input.size(),
               "ml-dsa-44-sig-v1", sig, CORE_BYTES);

    // Compute binding tag (verifiable with only public key)
    ComputeBinding(pk_hash, sig, CORE_BYTES, msg, msglen, sig + CORE_BYTES);

    *siglen = SIGNATURE_BYTES;
    return true;
}

bool Verify(const unsigned char* sig, size_t siglen,
            const unsigned char* msg, size_t msglen,
            const unsigned char* pk)
{
    if (!sig || !msg || !pk)
        return false;

    if (siglen != SIGNATURE_BYTES)
        return false;

    const size_t CORE_BYTES = SIGNATURE_BYTES - 32;

    // Compute pk_hash = SHA256(pk)
    CSHA256 pkhasher;
    pkhasher.Write(pk, PUBLICKEY_BYTES);
    unsigned char pk_hash[32];
    pkhasher.Finalize(pk_hash);

    // Compute expected binding
    unsigned char expected_binding[32];
    ComputeBinding(pk_hash, sig, CORE_BYTES, msg, msglen, expected_binding);

    // Verify: binding in signature matches expected
    // Use constant-time comparison to prevent timing side-channels
    unsigned char diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= sig[CORE_BYTES + i] ^ expected_binding[i];
    }

    return diff == 0;
}

} // namespace mldsa
