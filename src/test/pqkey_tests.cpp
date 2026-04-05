// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: Hybrid Key Unit Tests

#include "pqkey.h"
#include "crypto/mldsa.h"
#include "uint256.h"
#include "test/test_raven.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <vector>
#include <cstring>

BOOST_FIXTURE_TEST_SUITE(pqkey_tests, BasicTestingSetup)

// ============================================================
// ML-DSA-44 Low-Level Tests
// ============================================================

BOOST_AUTO_TEST_CASE(mldsa_keygen_deterministic)
{
    // Same seed must produce same keypair
    unsigned char seed[32];
    memset(seed, 0x42, 32);

    unsigned char pk1[mldsa::PUBLICKEY_BYTES], sk1[mldsa::SECRETKEY_BYTES];
    unsigned char pk2[mldsa::PUBLICKEY_BYTES], sk2[mldsa::SECRETKEY_BYTES];

    BOOST_CHECK(mldsa::KeyGen(pk1, sk1, seed));
    BOOST_CHECK(mldsa::KeyGen(pk2, sk2, seed));

    BOOST_CHECK(memcmp(pk1, pk2, mldsa::PUBLICKEY_BYTES) == 0);
    BOOST_CHECK(memcmp(sk1, sk2, mldsa::SECRETKEY_BYTES) == 0);
}

BOOST_AUTO_TEST_CASE(mldsa_keygen_different_seeds)
{
    // Different seeds must produce different keypairs
    unsigned char seed1[32], seed2[32];
    memset(seed1, 0x01, 32);
    memset(seed2, 0x02, 32);

    unsigned char pk1[mldsa::PUBLICKEY_BYTES], sk1[mldsa::SECRETKEY_BYTES];
    unsigned char pk2[mldsa::PUBLICKEY_BYTES], sk2[mldsa::SECRETKEY_BYTES];

    BOOST_CHECK(mldsa::KeyGen(pk1, sk1, seed1));
    BOOST_CHECK(mldsa::KeyGen(pk2, sk2, seed2));

    BOOST_CHECK(memcmp(pk1, pk2, mldsa::PUBLICKEY_BYTES) != 0);
}

BOOST_AUTO_TEST_CASE(mldsa_sign_verify_roundtrip)
{
    // Sign and verify must succeed for matching key/message
    unsigned char seed[32];
    memset(seed, 0xAB, 32);

    unsigned char pk[mldsa::PUBLICKEY_BYTES], sk[mldsa::SECRETKEY_BYTES];
    BOOST_CHECK(mldsa::KeyGen(pk, sk, seed));

    unsigned char msg[] = "RIP-25 test message for ML-DSA-44";
    size_t msglen = sizeof(msg) - 1;

    unsigned char sig[mldsa::SIGNATURE_BYTES];
    size_t siglen = 0;
    BOOST_CHECK(mldsa::Sign(sig, &siglen, msg, msglen, sk));
    BOOST_CHECK_EQUAL(siglen, mldsa::SIGNATURE_BYTES);

    // Verify with correct key and message
    BOOST_CHECK(mldsa::Verify(sig, siglen, msg, msglen, pk));
}

BOOST_AUTO_TEST_CASE(mldsa_verify_wrong_message)
{
    // Verification must fail for wrong message
    unsigned char seed[32];
    memset(seed, 0xCD, 32);

    unsigned char pk[mldsa::PUBLICKEY_BYTES], sk[mldsa::SECRETKEY_BYTES];
    BOOST_CHECK(mldsa::KeyGen(pk, sk, seed));

    unsigned char msg1[] = "correct message";
    unsigned char msg2[] = "wrong message!!";

    unsigned char sig[mldsa::SIGNATURE_BYTES];
    size_t siglen = 0;
    BOOST_CHECK(mldsa::Sign(sig, &siglen, msg1, sizeof(msg1) - 1, sk));

    // Must fail with different message
    BOOST_CHECK(!mldsa::Verify(sig, siglen, msg2, sizeof(msg2) - 1, pk));
}

BOOST_AUTO_TEST_CASE(mldsa_verify_wrong_key)
{
    // Verification must fail for wrong public key
    unsigned char seed1[32], seed2[32];
    memset(seed1, 0x11, 32);
    memset(seed2, 0x22, 32);

    unsigned char pk1[mldsa::PUBLICKEY_BYTES], sk1[mldsa::SECRETKEY_BYTES];
    unsigned char pk2[mldsa::PUBLICKEY_BYTES], sk2[mldsa::SECRETKEY_BYTES];

    BOOST_CHECK(mldsa::KeyGen(pk1, sk1, seed1));
    BOOST_CHECK(mldsa::KeyGen(pk2, sk2, seed2));

    unsigned char msg[] = "test message";
    unsigned char sig[mldsa::SIGNATURE_BYTES];
    size_t siglen = 0;
    BOOST_CHECK(mldsa::Sign(sig, &siglen, msg, sizeof(msg) - 1, sk1));

    // Must succeed with correct key
    BOOST_CHECK(mldsa::Verify(sig, siglen, msg, sizeof(msg) - 1, pk1));

    // Must fail with wrong key
    BOOST_CHECK(!mldsa::Verify(sig, siglen, msg, sizeof(msg) - 1, pk2));
}

BOOST_AUTO_TEST_CASE(mldsa_verify_tampered_signature)
{
    // Verification must fail for tampered signature
    unsigned char seed[32];
    memset(seed, 0xEF, 32);

    unsigned char pk[mldsa::PUBLICKEY_BYTES], sk[mldsa::SECRETKEY_BYTES];
    BOOST_CHECK(mldsa::KeyGen(pk, sk, seed));

    unsigned char msg[] = "tamper test";
    unsigned char sig[mldsa::SIGNATURE_BYTES];
    size_t siglen = 0;
    BOOST_CHECK(mldsa::Sign(sig, &siglen, msg, sizeof(msg) - 1, sk));

    // Tamper with signature
    sig[100] ^= 0xFF;

    BOOST_CHECK(!mldsa::Verify(sig, siglen, msg, sizeof(msg) - 1, pk));
}

BOOST_AUTO_TEST_CASE(mldsa_verify_wrong_siglen)
{
    unsigned char seed[32];
    memset(seed, 0x33, 32);

    unsigned char pk[mldsa::PUBLICKEY_BYTES], sk[mldsa::SECRETKEY_BYTES];
    BOOST_CHECK(mldsa::KeyGen(pk, sk, seed));

    unsigned char msg[] = "size test";
    unsigned char sig[mldsa::SIGNATURE_BYTES];
    size_t siglen = 0;
    BOOST_CHECK(mldsa::Sign(sig, &siglen, msg, sizeof(msg) - 1, sk));

    // Wrong signature length must fail
    BOOST_CHECK(!mldsa::Verify(sig, siglen - 1, msg, sizeof(msg) - 1, pk));
    BOOST_CHECK(!mldsa::Verify(sig, 0, msg, sizeof(msg) - 1, pk));
}

BOOST_AUTO_TEST_CASE(mldsa_sign_deterministic)
{
    // Same (sk, msg) must produce same signature
    unsigned char seed[32];
    memset(seed, 0x77, 32);

    unsigned char pk[mldsa::PUBLICKEY_BYTES], sk[mldsa::SECRETKEY_BYTES];
    BOOST_CHECK(mldsa::KeyGen(pk, sk, seed));

    unsigned char msg[] = "determinism test";

    unsigned char sig1[mldsa::SIGNATURE_BYTES], sig2[mldsa::SIGNATURE_BYTES];
    size_t siglen1 = 0, siglen2 = 0;

    BOOST_CHECK(mldsa::Sign(sig1, &siglen1, msg, sizeof(msg) - 1, sk));
    BOOST_CHECK(mldsa::Sign(sig2, &siglen2, msg, sizeof(msg) - 1, sk));

    BOOST_CHECK(memcmp(sig1, sig2, mldsa::SIGNATURE_BYTES) == 0);
}

BOOST_AUTO_TEST_CASE(mldsa_sizes_correct)
{
    // Verify constants match FIPS 204 ML-DSA-44
    BOOST_CHECK_EQUAL(mldsa::PUBLICKEY_BYTES, 1312u);
    BOOST_CHECK_EQUAL(mldsa::SECRETKEY_BYTES, 2560u);
    BOOST_CHECK_EQUAL(mldsa::SIGNATURE_BYTES, 2420u);
    BOOST_CHECK_EQUAL(mldsa::SEED_BYTES, 32u);
}

// ============================================================
// Hybrid Key Tests
// ============================================================

BOOST_AUTO_TEST_CASE(hybrid_key_generation)
{
    CHybridKey key;

    // Generate with random seed
    BOOST_CHECK(key.MakeNewKey());
    BOOST_CHECK(key.IsValid());

    // Get public key
    CHybridPubKey pub = key.GetPubKey();
    BOOST_CHECK(pub.IsValid());
    BOOST_CHECK_EQUAL(pub.size(), CHybridPubKey::HYBRID_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(pub.GetType(), HYBRID_KEY_TYPE_MLDSA44);
}

BOOST_AUTO_TEST_CASE(hybrid_key_deterministic)
{
    // Same master seed must produce same hybrid keypair
    unsigned char seed[32];
    memset(seed, 0xBE, 32);

    CHybridKey key1, key2;
    BOOST_CHECK(key1.MakeNewKey(seed));
    BOOST_CHECK(key2.MakeNewKey(seed));

    CHybridPubKey pub1 = key1.GetPubKey();
    CHybridPubKey pub2 = key2.GetPubKey();

    BOOST_CHECK(memcmp(pub1.data(), pub2.data(), pub1.size()) == 0);
}

BOOST_AUTO_TEST_CASE(hybrid_sign_verify_roundtrip)
{
    CHybridKey key;
    BOOST_CHECK(key.MakeNewKey());

    CHybridPubKey pub = key.GetPubKey();
    BOOST_CHECK(pub.IsValid());

    // Create a mock transaction hash
    uint256 hash;
    memset(hash.begin(), 0xAA, 32);

    // Sign
    std::vector<unsigned char> ecdsa_sig, mldsa_sig;
    BOOST_CHECK(key.Sign(hash, ecdsa_sig, mldsa_sig));

    // Check signature sizes
    BOOST_CHECK(ecdsa_sig.size() > 0 && ecdsa_sig.size() <= 72);
    BOOST_CHECK_EQUAL(mldsa_sig.size(), mldsa::SIGNATURE_BYTES);

    // Verify
    BOOST_CHECK(pub.Verify(hash, ecdsa_sig, mldsa_sig));
}

BOOST_AUTO_TEST_CASE(hybrid_verify_wrong_hash)
{
    CHybridKey key;
    BOOST_CHECK(key.MakeNewKey());

    CHybridPubKey pub = key.GetPubKey();

    uint256 hash1, hash2;
    memset(hash1.begin(), 0xAA, 32);
    memset(hash2.begin(), 0xBB, 32);

    std::vector<unsigned char> ecdsa_sig, mldsa_sig;
    BOOST_CHECK(key.Sign(hash1, ecdsa_sig, mldsa_sig));

    // Must fail with different hash
    BOOST_CHECK(!pub.Verify(hash2, ecdsa_sig, mldsa_sig));
}

BOOST_AUTO_TEST_CASE(hybrid_verify_wrong_pubkey)
{
    CHybridKey key1, key2;
    BOOST_CHECK(key1.MakeNewKey());
    BOOST_CHECK(key2.MakeNewKey());

    CHybridPubKey pub2 = key2.GetPubKey();

    uint256 hash;
    memset(hash.begin(), 0xCC, 32);

    // Sign with key1
    std::vector<unsigned char> ecdsa_sig, mldsa_sig;
    BOOST_CHECK(key1.Sign(hash, ecdsa_sig, mldsa_sig));

    // Verify with key2's pubkey must fail
    BOOST_CHECK(!pub2.Verify(hash, ecdsa_sig, mldsa_sig));
}

BOOST_AUTO_TEST_CASE(hybrid_verify_partial_signature_ecdsa_only)
{
    CHybridKey key;
    BOOST_CHECK(key.MakeNewKey());

    CHybridPubKey pub = key.GetPubKey();

    uint256 hash;
    memset(hash.begin(), 0xDD, 32);

    std::vector<unsigned char> ecdsa_sig, mldsa_sig;
    BOOST_CHECK(key.Sign(hash, ecdsa_sig, mldsa_sig));

    // Tamper with ML-DSA signature (valid ECDSA + invalid ML-DSA)
    std::vector<unsigned char> bad_mldsa(mldsa_sig);
    bad_mldsa[500] ^= 0xFF;

    BOOST_CHECK(!pub.Verify(hash, ecdsa_sig, bad_mldsa));
}

BOOST_AUTO_TEST_CASE(hybrid_verify_partial_signature_mldsa_only)
{
    CHybridKey key;
    BOOST_CHECK(key.MakeNewKey());

    CHybridPubKey pub = key.GetPubKey();

    uint256 hash;
    memset(hash.begin(), 0xEE, 32);

    std::vector<unsigned char> ecdsa_sig, mldsa_sig;
    BOOST_CHECK(key.Sign(hash, ecdsa_sig, mldsa_sig));

    // Tamper with ECDSA signature (invalid ECDSA + valid ML-DSA)
    std::vector<unsigned char> bad_ecdsa(ecdsa_sig);
    if (bad_ecdsa.size() > 5)
        bad_ecdsa[5] ^= 0xFF;

    BOOST_CHECK(!pub.Verify(hash, bad_ecdsa, mldsa_sig));
}

BOOST_AUTO_TEST_CASE(hybrid_witness_program)
{
    CHybridKey key;
    BOOST_CHECK(key.MakeNewKey());

    CHybridPubKey pub = key.GetPubKey();

    // Witness program must be 32 bytes (SHA256 hash)
    uint256 wp = pub.GetWitnessProgram();
    BOOST_CHECK(!wp.IsNull());

    // Same key must produce same witness program
    CHybridPubKey pub2 = key.GetPubKey();
    uint256 wp2 = pub2.GetWitnessProgram();
    BOOST_CHECK(wp == wp2);
}

BOOST_AUTO_TEST_CASE(hybrid_pubkey_serialization)
{
    CHybridKey key;
    BOOST_CHECK(key.MakeNewKey());

    CHybridPubKey pub = key.GetPubKey();

    // Serialize
    std::vector<unsigned char> serialized = pub.Serialize();
    BOOST_CHECK_EQUAL(serialized.size(), CHybridPubKey::HYBRID_PUBKEY_SIZE);

    // Deserialize
    CHybridPubKey pub2;
    BOOST_CHECK(pub2.Deserialize(serialized.data(), serialized.size()));
    BOOST_CHECK(pub2.IsValid());

    // Must match original
    BOOST_CHECK(memcmp(pub.data(), pub2.data(), pub.size()) == 0);
}

BOOST_AUTO_TEST_CASE(hybrid_pubkey_deserialize_invalid)
{
    CHybridPubKey pub;

    // Wrong size
    unsigned char bad_data[100];
    memset(bad_data, 0, 100);
    BOOST_CHECK(!pub.Deserialize(bad_data, 100));
    BOOST_CHECK(!pub.IsValid());

    // Wrong type byte
    unsigned char bad_type[CHybridPubKey::HYBRID_PUBKEY_SIZE];
    memset(bad_type, 0, sizeof(bad_type));
    bad_type[0] = 0xFF; // invalid type
    BOOST_CHECK(!pub.Deserialize(bad_type, sizeof(bad_type)));
}

BOOST_AUTO_TEST_CASE(hybrid_ecdsa_component_works)
{
    CHybridKey key;
    BOOST_CHECK(key.MakeNewKey());

    CHybridPubKey pub = key.GetPubKey();

    // Extract ECDSA component
    CPubKey ecdsaPub = pub.GetECDSAPubKey();
    BOOST_CHECK(ecdsaPub.IsCompressed());
    BOOST_CHECK(ecdsaPub.IsValid());

    // Verify the ECDSA component independently
    uint256 hash;
    memset(hash.begin(), 0xFF, 32);

    std::vector<unsigned char> ecdsa_sig;
    BOOST_CHECK(key.GetECDSAKey().Sign(hash, ecdsa_sig));
    BOOST_CHECK(ecdsaPub.Verify(hash, ecdsa_sig));
}

BOOST_AUTO_TEST_CASE(hybrid_multiple_signatures_same_key)
{
    CHybridKey key;
    BOOST_CHECK(key.MakeNewKey());

    CHybridPubKey pub = key.GetPubKey();

    // Sign multiple different messages
    for (int i = 0; i < 10; i++) {
        uint256 hash;
        memset(hash.begin(), i, 32);

        std::vector<unsigned char> ecdsa_sig, mldsa_sig;
        BOOST_CHECK(key.Sign(hash, ecdsa_sig, mldsa_sig));
        BOOST_CHECK(pub.Verify(hash, ecdsa_sig, mldsa_sig));
    }
}

BOOST_AUTO_TEST_SUITE_END()
