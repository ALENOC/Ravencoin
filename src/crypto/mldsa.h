// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: ML-DSA-44 Post-Quantum Signature Wrapper
// This is a proof-of-concept implementation using a standalone ML-DSA-44
// reference. Production code will use liboqs.

#ifndef RAVEN_CRYPTO_MLDSA_H
#define RAVEN_CRYPTO_MLDSA_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace mldsa {

// ML-DSA-44 (FIPS 204) constants
static const size_t PUBLICKEY_BYTES  = 1312;
static const size_t SECRETKEY_BYTES  = 2560;
static const size_t SIGNATURE_BYTES  = 2420;
static const size_t SEED_BYTES       = 32;

/**
 * Generate an ML-DSA-44 keypair from a 32-byte seed.
 * Deterministic: same seed always produces the same keypair.
 *
 * @param[out] pk  Public key buffer (must be PUBLICKEY_BYTES)
 * @param[out] sk  Secret key buffer (must be SECRETKEY_BYTES)
 * @param[in]  seed 32-byte seed
 * @return true on success
 */
bool KeyGen(unsigned char* pk, unsigned char* sk, const unsigned char* seed);

/**
 * Generate an ML-DSA-44 keypair from random entropy.
 *
 * @param[out] pk  Public key buffer (must be PUBLICKEY_BYTES)
 * @param[out] sk  Secret key buffer (must be SECRETKEY_BYTES)
 * @return true on success
 */
bool KeyGenRandom(unsigned char* pk, unsigned char* sk);

/**
 * Sign a message using ML-DSA-44.
 *
 * @param[out] sig     Signature buffer (must be SIGNATURE_BYTES)
 * @param[out] siglen  Actual signature length (always SIGNATURE_BYTES for ML-DSA-44)
 * @param[in]  msg     Message to sign
 * @param[in]  msglen  Message length
 * @param[in]  sk      Secret key (SECRETKEY_BYTES)
 * @return true on success
 */
bool Sign(unsigned char* sig, size_t* siglen,
          const unsigned char* msg, size_t msglen,
          const unsigned char* sk);

/**
 * Verify an ML-DSA-44 signature.
 *
 * @param[in] sig     Signature (SIGNATURE_BYTES)
 * @param[in] siglen  Signature length
 * @param[in] msg     Message
 * @param[in] msglen  Message length
 * @param[in] pk      Public key (PUBLICKEY_BYTES)
 * @return true if signature is valid
 */
bool Verify(const unsigned char* sig, size_t siglen,
            const unsigned char* msg, size_t msglen,
            const unsigned char* pk);

} // namespace mldsa

#endif // RAVEN_CRYPTO_MLDSA_H
