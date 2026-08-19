// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: ML-DSA-44 (FIPS 204) Post-Quantum Digital Signature Wrapper
// Uses liboqs (Open Quantum Safe) for the underlying implementation.

#ifndef RAVEN_CRYPTO_MLDSA_H
#define RAVEN_CRYPTO_MLDSA_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace mldsa {

// ML-DSA-44 (FIPS 204) constants — must match OQS_SIG_ml_dsa_44 values
static const size_t PUBLICKEY_BYTES  = 1312;
static const size_t SECRETKEY_BYTES  = 2560;
static const size_t SIGNATURE_BYTES  = 2420;
static const size_t SEED_BYTES       = 32;

/**
 * Attempt deterministic ML-DSA-44 key generation from a 32-byte seed.
 *
 * The pinned liboqs 0.12.0 public signature API does not provide deterministic
 * key generation. This function therefore fails closed instead of relying on
 * private liboqs symbols or silently substituting random key generation.
 *
 * @param[out] pk   Public key buffer (must be PUBLICKEY_BYTES)
 * @param[out] sk   Secret key buffer (must be SECRETKEY_BYTES)
 * @param[in]  seed 32-byte seed
 * @return false with liboqs 0.12.0; reserved for a future pinned public API
 */
bool KeyGen(unsigned char* pk, unsigned char* sk, const unsigned char* seed);

/**
 * Generate an ML-DSA-44 keypair from random entropy using the public liboqs API.
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

/** Verify an ML-DSA-44 signature. */
bool Verify(const unsigned char* sig, size_t siglen,
            const unsigned char* msg, size_t msglen,
            const unsigned char* pk);

} // namespace mldsa

#endif // RAVEN_CRYPTO_MLDSA_H
