// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: adversarial regression tests for PQ key/wallet and v4.8 port hardening.

#include "chainparams.h"
#include "consensus/consensus.h"
#include "crypto/mldsa.h"
#include "pqkey.h"
#include "test/test_raven.h"

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <memory>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(pqkey_hardening_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rip25_v48_consensus_constants_and_deployment_bits)
{
    std::unique_ptr<CChainParams> mainParams = CreateChainParams("main");
    BOOST_REQUIRE(mainParams);
    const Consensus::Params& consensus = mainParams->GetConsensus();

    // Ravencoin 4.8.0 owns bit 11; RIP-25 moves only its signaling bit to 12.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].bit, 11);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].bit, 12);

    // August-2026 forged header-height protection must remain present.
    BOOST_CHECK_EQUAL(consensus.nHeightHeaderCheckActivation, 4487776);

    const auto checkpoint = mainParams->Checkpoints().mapCheckpoints.find(4487775);
    BOOST_REQUIRE(checkpoint != mainParams->Checkpoints().mapCheckpoints.end());
    BOOST_CHECK(checkpoint->second == uint256S("0x000000000002d64509e06e76ddbbe418c725291687ec62b41ecfc40386a091fd"));

    // Approved RIP-25 resource policy is an invariant of the 4.8 port.
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT_RIP2, 8000000u);
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT_RIP25_PHASE1, 12000000u);
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT_RIP25_PHASE2, 16000000u);
    BOOST_CHECK_EQUAL(PQ_WITNESS_SCALE_FACTOR, 8);
}

BOOST_AUTO_TEST_CASE(mldsa_rejects_null_inputs)
{
    unsigned char seed[mldsa::SEED_BYTES];
    std::memset(seed, 0x42, sizeof(seed));

    unsigned char pk[mldsa::PUBLICKEY_BYTES];
    unsigned char sk[mldsa::SECRETKEY_BYTES];
    unsigned char sig[mldsa::SIGNATURE_BYTES];
    size_t siglen = 0;
    const unsigned char msg[] = "RIP-25 null input regression";

    BOOST_CHECK(!mldsa::KeyGen(nullptr, sk, seed));
    BOOST_CHECK(!mldsa::KeyGen(pk, nullptr, seed));
    BOOST_CHECK(!mldsa::KeyGen(pk, sk, nullptr));
    BOOST_CHECK(!mldsa::KeyGenRandom(nullptr, sk));
    BOOST_CHECK(!mldsa::KeyGenRandom(pk, nullptr));

    BOOST_REQUIRE(mldsa::KeyGen(pk, sk, seed));
    BOOST_CHECK(!mldsa::Sign(nullptr, &siglen, msg, sizeof(msg) - 1, sk));
    BOOST_CHECK(!mldsa::Sign(sig, nullptr, msg, sizeof(msg) - 1, sk));
    BOOST_CHECK(!mldsa::Sign(sig, &siglen, nullptr, sizeof(msg) - 1, sk));
    BOOST_CHECK(!mldsa::Sign(sig, &siglen, msg, sizeof(msg) - 1, nullptr));
    BOOST_CHECK(!mldsa::Verify(nullptr, mldsa::SIGNATURE_BYTES, msg, sizeof(msg) - 1, pk));
    BOOST_CHECK(!mldsa::Verify(sig, mldsa::SIGNATURE_BYTES, nullptr, sizeof(msg) - 1, pk));
    BOOST_CHECK(!mldsa::Verify(sig, mldsa::SIGNATURE_BYTES, msg, sizeof(msg) - 1, nullptr));
}

BOOST_AUTO_TEST_CASE(deterministic_keygen_restores_system_rng)
{
    unsigned char seed[mldsa::SEED_BYTES];
    std::memset(seed, 0x5a, sizeof(seed));

    unsigned char pk1[mldsa::PUBLICKEY_BYTES], sk1[mldsa::SECRETKEY_BYTES];
    unsigned char pk2[mldsa::PUBLICKEY_BYTES], sk2[mldsa::SECRETKEY_BYTES];
    unsigned char randomPk[mldsa::PUBLICKEY_BYTES], randomSk[mldsa::SECRETKEY_BYTES];

    BOOST_REQUIRE(mldsa::KeyGen(pk1, sk1, seed));
    BOOST_REQUIRE(mldsa::KeyGenRandom(randomPk, randomSk));
    BOOST_REQUIRE(mldsa::KeyGen(pk2, sk2, seed));

    BOOST_CHECK(std::memcmp(pk1, pk2, mldsa::PUBLICKEY_BYTES) == 0);
    BOOST_CHECK(std::memcmp(sk1, sk2, mldsa::SECRETKEY_BYTES) == 0);
}

BOOST_AUTO_TEST_CASE(secret_public_key_binding)
{
    CPQKey key1;
    CPQKey key2;
    key1.MakeNewKey();
    key2.MakeNewKey();
    BOOST_REQUIRE(key1.IsValid());
    BOOST_REQUIRE(key2.IsValid());

    const CPQPubKey pub1 = key1.GetPubKey();
    const CPQPubKey pub2 = key2.GetPubKey();

    BOOST_CHECK(key1.MatchesPubKey(pub1));
    BOOST_CHECK(!key1.MatchesPubKey(pub2));
    BOOST_CHECK(key2.MatchesPubKey(pub2));
    BOOST_CHECK(!key2.MatchesPubKey(pub1));
}

BOOST_AUTO_TEST_CASE(import_matching_secret_public_key_pair)
{
    CPQKey source;
    source.MakeNewKey();
    BOOST_REQUIRE(source.IsValid());

    const CPQPubKey expectedPub = source.GetPubKey();
    const auto& secret = source.GetKeyData();
    std::vector<unsigned char> raw(secret.begin(), secret.end());

    CPQKey imported;
    BOOST_REQUIRE(imported.SetKeyData(raw, expectedPub));
    BOOST_CHECK(imported.IsValid());
    BOOST_CHECK(imported.GetPubKey() == expectedPub);
    BOOST_CHECK(imported.MatchesPubKey(expectedPub));
}

BOOST_AUTO_TEST_CASE(import_rejects_mismatched_public_key_and_invalidates_key)
{
    CPQKey source;
    CPQKey other;
    source.MakeNewKey();
    other.MakeNewKey();
    BOOST_REQUIRE(source.IsValid());
    BOOST_REQUIRE(other.IsValid());

    const auto& secret = source.GetKeyData();
    std::vector<unsigned char> raw(secret.begin(), secret.end());
    const CPQPubKey wrongPub = other.GetPubKey();

    CPQKey imported;
    BOOST_CHECK(!imported.SetKeyData(raw, wrongPub));
    BOOST_CHECK(!imported.IsValid());
    BOOST_CHECK(!imported.GetPubKey().IsValid());

    uint256 hash;
    std::memset(hash.begin(), 0xa5, 32);
    std::vector<unsigned char> signature;
    BOOST_CHECK(!imported.Sign(hash, signature));
}

BOOST_AUTO_TEST_CASE(import_rejects_wrong_secret_size)
{
    CPQKey key;
    CPQKey pubSource;
    pubSource.MakeNewKey();
    BOOST_REQUIRE(pubSource.IsValid());

    std::vector<unsigned char> tooShort(mldsa::SECRETKEY_BYTES - 1, 0);
    std::vector<unsigned char> tooLong(mldsa::SECRETKEY_BYTES + 1, 0);

    BOOST_CHECK(!key.SetKeyData(tooShort, pubSource.GetPubKey()));
    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK(!key.SetKeyData(tooLong, pubSource.GetPubKey()));
    BOOST_CHECK(!key.IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
