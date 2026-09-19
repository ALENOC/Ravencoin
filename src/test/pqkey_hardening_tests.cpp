// Copyright (c) 2026 ALENOC (https://github.com/ALENOC)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RIP-25: adversarial regression tests for PQ key/wallet and v4.8 port hardening.

#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/rip25.h"
#include "consensus/validation.h"
#include "crypto/mldsa.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "keystore.h"
#include "policy/policy.h"
#include "pqkey.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/sign.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_raven.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <type_traits>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(pqkey_hardening_tests, BasicTestingSetup)

namespace {

static const unsigned char TEST_CONTEXT[] = "RVN/ML-DSA-44/unit-test/v1";

const Consensus::PQSignatureContext& NetworkContext(const char* network)
{
    static const std::unique_ptr<CChainParams> mainParams = CreateChainParams("main");
    static const std::unique_ptr<CChainParams> testParams = CreateChainParams("test");
    static const std::unique_ptr<CChainParams> regtestParams = CreateChainParams("regtest");

    if (std::strcmp(network, "main") == 0)
        return mainParams->GetConsensus().pqSignatureContext;
    if (std::strcmp(network, "test") == 0)
        return testParams->GetConsensus().pqSignatureContext;
    return regtestParams->GetConsensus().pqSignatureContext;
}

} // namespace

BOOST_AUTO_TEST_CASE(pq_secret_material_uses_secure_allocator_and_legacy_encoding)
{
    static_assert(std::is_same<CPQKey::KeyData::allocator_type,
                               secure_allocator<unsigned char>>::value,
                  "PQ secret keys require secure_allocator");

    const CPQKey::KeyData secureSecret(mldsa::SECRETKEY_BYTES, 0x5a);
    const std::vector<unsigned char> legacySecret(secureSecret.begin(), secureSecret.end());

    CDataStream secureEncoding(SER_DISK, 0);
    CDataStream legacyEncoding(SER_DISK, 0);
    secureEncoding << secureSecret;
    legacyEncoding << legacySecret;
    BOOST_CHECK_EQUAL_COLLECTIONS(secureEncoding.begin(), secureEncoding.end(),
                                  legacyEncoding.begin(), legacyEncoding.end());

    const std::vector<unsigned char> pubkeyBytes(mldsa::PUBLICKEY_BYTES, 0x33);
    const CPQPubKey pubkey(pubkeyBytes);
    std::vector<unsigned char> legacyHashInput(pubkey.begin(), pubkey.end());
    legacyHashInput.insert(legacyHashInput.end(), legacySecret.begin(), legacySecret.end());
    BOOST_CHECK(Hash(legacyHashInput.begin(), legacyHashInput.end()) ==
                Hash(pubkey.begin(), pubkey.end(), secureSecret.begin(), secureSecret.end()));
}

BOOST_AUTO_TEST_CASE(rip25_v48_consensus_constants_and_deployment_bits)
{
    std::unique_ptr<CChainParams> mainParams = CreateChainParams("main");
    BOOST_REQUIRE(mainParams);
    const Consensus::Params& consensus = mainParams->GetConsensus();

    // Ravencoin 4.8.0 owns bit 11; RIP-25 moves only its signaling bit to 12.
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].bit, 11);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].bit, 12);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].nOverrideRuleChangeActivationThreshold, 1411);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_OVERFLOW].nOverrideMinerConfirmationWindow, 2016);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].nOverrideRuleChangeActivationThreshold, 1714);
    BOOST_CHECK_EQUAL(consensus.vDeployments[Consensus::DEPLOYMENT_PQ_HYBRID].nOverrideMinerConfirmationWindow, 2016);

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

BOOST_AUTO_TEST_CASE(rip25_network_signature_contexts_are_canonical)
{
    const Consensus::PQSignatureContext& mainContext = NetworkContext("main");
    const Consensus::PQSignatureContext& testContext = NetworkContext("test");
    const Consensus::PQSignatureContext& regtestContext = NetworkContext("regtest");

    BOOST_REQUIRE(Consensus::IsValidPQSignatureContext(mainContext));
    BOOST_REQUIRE(Consensus::IsValidPQSignatureContext(testContext));
    BOOST_REQUIRE(Consensus::IsValidPQSignatureContext(regtestContext));
    BOOST_CHECK(mainContext != testContext);
    BOOST_CHECK(mainContext != regtestContext);
    BOOST_CHECK(testContext != regtestContext);

    BOOST_CHECK_EQUAL(std::string(mainContext.begin(), mainContext.end()),
        "RVN/ML-DSA-44/v1/0000006b444bc2f2ffe627be9d9e7e7a0730000870ef6eb6da46c8eae389df90");
    BOOST_CHECK_EQUAL(std::string(testContext.begin(), testContext.end()),
        "RVN/ML-DSA-44/v1/000000ecfc5e6324a079542221d00e10362bdc894d56500c414060eea8a3ad5a");
    BOOST_CHECK_EQUAL(std::string(regtestContext.begin(), regtestContext.end()),
        "RVN/ML-DSA-44/v1/0b2c703dc93bb63a36c4e33b85be4855ddbca2ac951a7a0a29b8de0408200a3c");
}

BOOST_AUTO_TEST_CASE(rip25_block_weight_phase_boundaries)
{
    std::unique_ptr<CChainParams> mainParams = CreateChainParams("main");
    std::unique_ptr<CChainParams> regtestParams = CreateChainParams("regtest");
    BOOST_REQUIRE(mainParams);
    BOOST_REQUIRE(regtestParams);

    // Mainnet is not force-enabled: with no active chain state the RIP-2 ceiling remains 8 MWU.
    BOOST_CHECK_EQUAL(GetMaxBlockWeightForPrev(nullptr, mainParams->GetConsensus()), MAX_BLOCK_WEIGHT_RIP2);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeForPrev(nullptr, mainParams->GetConsensus()), MAX_BLOCK_SERIALIZED_SIZE_RIP2);

    const Consensus::Params& regtest = regtestParams->GetConsensus();
    BOOST_REQUIRE(regtest.nPQHybridEnabled);
    BOOST_REQUIRE(regtest.nPowTargetSpacing > 0);

    const int64_t blocksPerYear = (365LL * 24 * 60 * 60) / regtest.nPowTargetSpacing;
    BOOST_REQUIRE(blocksPerYear > 1);

    CBlockIndex prev;
    prev.nHeight = 0;
    BOOST_CHECK_EQUAL(GetMaxBlockWeightForPrev(&prev, regtest), MAX_BLOCK_WEIGHT_RIP25_PHASE1);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeForPrev(&prev, regtest), MAX_BLOCK_SERIALIZED_SIZE_RIP25_PHASE1);

    // Candidate height activation + blocksPerYear - 1 is still Phase 1.
    prev.nHeight = static_cast<int>(blocksPerYear - 2);
    BOOST_CHECK_EQUAL(GetMaxBlockWeightForPrev(&prev, regtest), MAX_BLOCK_WEIGHT_RIP25_PHASE1);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeForPrev(&prev, regtest), MAX_BLOCK_SERIALIZED_SIZE_RIP25_PHASE1);

    // Candidate height activation + blocksPerYear is the first Phase-2 block.
    prev.nHeight = static_cast<int>(blocksPerYear - 1);
    BOOST_CHECK_EQUAL(GetMaxBlockWeightForPrev(&prev, regtest), MAX_BLOCK_WEIGHT_RIP25_PHASE2);
    BOOST_CHECK_EQUAL(GetMaxBlockSerializedSizeForPrev(&prev, regtest), MAX_BLOCK_SERIALIZED_SIZE_RIP25_PHASE2);
}

BOOST_AUTO_TEST_CASE(rip25_approved_pq_witness_discount_accounting)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    mtx.vin[0].scriptWitness.stack.emplace_back(mldsa::SIGNATURE_BYTES, 0x11);
    mtx.vin[0].scriptWitness.stack.emplace_back(mldsa::PUBLICKEY_BYTES, 0x22);

    const CTransaction tx(mtx);
    const int64_t standardWeight = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1)
                                 + ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    const int64_t pqBytes = mldsa::SIGNATURE_BYTES + mldsa::PUBLICKEY_BYTES;
    const int64_t expectedDiscount = pqBytes * (PQ_WITNESS_SCALE_FACTOR - WITNESS_SCALE_FACTOR) / PQ_WITNESS_SCALE_FACTOR;

    BOOST_CHECK_EQUAL(GetPQWitnessInputDiscount(tx.vin[0]), expectedDiscount);
    BOOST_CHECK_EQUAL(GetTransactionWeight(tx), standardWeight - expectedDiscount);

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(mtx));
    BOOST_CHECK_EQUAL(GetBlockWeightRIP25(block), GetBlockWeight(block) - expectedDiscount);

    // Shape mismatch must not receive the approved PQ discount.
    CMutableTransaction malformed = mtx;
    malformed.vin[0].scriptWitness.stack[0].resize(mldsa::SIGNATURE_BYTES - 1);
    const CTransaction malformedTx(malformed);
    const int64_t malformedStandardWeight = ::GetSerializeSize(malformedTx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1)
                                          + ::GetSerializeSize(malformedTx, SER_NETWORK, PROTOCOL_VERSION);
    BOOST_CHECK_EQUAL(GetPQWitnessInputDiscount(malformedTx.vin[0]), 0);
    BOOST_CHECK_EQUAL(GetTransactionWeight(malformedTx), malformedStandardWeight);
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

    std::memset(pk, 0x5a, sizeof(pk));
    std::memset(sk, 0x5a, sizeof(sk));
    BOOST_CHECK(!mldsa::KeyGen(nullptr, sk, seed));
    BOOST_CHECK(std::all_of(std::begin(sk), std::end(sk), [](unsigned char byte) { return byte == 0; }));

    std::memset(pk, 0x5a, sizeof(pk));
    BOOST_CHECK(!mldsa::KeyGen(pk, nullptr, seed));
    BOOST_CHECK(std::all_of(std::begin(pk), std::end(pk), [](unsigned char byte) { return byte == 0; }));

    std::memset(pk, 0x5a, sizeof(pk));
    std::memset(sk, 0x5a, sizeof(sk));
    BOOST_CHECK(!mldsa::KeyGen(pk, sk, nullptr));
    BOOST_CHECK(std::all_of(std::begin(pk), std::end(pk), [](unsigned char byte) { return byte == 0; }));
    BOOST_CHECK(std::all_of(std::begin(sk), std::end(sk), [](unsigned char byte) { return byte == 0; }));

    std::memset(sk, 0x5a, sizeof(sk));
    BOOST_CHECK(!mldsa::KeyGenRandom(nullptr, sk));
    BOOST_CHECK(std::all_of(std::begin(sk), std::end(sk), [](unsigned char byte) { return byte == 0; }));

    std::memset(pk, 0x5a, sizeof(pk));
    BOOST_CHECK(!mldsa::KeyGenRandom(pk, nullptr));
    BOOST_CHECK(std::all_of(std::begin(pk), std::end(pk), [](unsigned char byte) { return byte == 0; }));

    BOOST_REQUIRE(mldsa::KeyGen(pk, sk, seed));
    siglen = 123;
    BOOST_CHECK(!mldsa::Sign(nullptr, &siglen, msg, sizeof(msg) - 1,
                             TEST_CONTEXT, sizeof(TEST_CONTEXT) - 1, sk));
    BOOST_CHECK_EQUAL(siglen, 0U);
    BOOST_CHECK(!mldsa::Sign(sig, nullptr, msg, sizeof(msg) - 1,
                             TEST_CONTEXT, sizeof(TEST_CONTEXT) - 1, sk));
    BOOST_CHECK(!mldsa::Sign(sig, &siglen, nullptr, sizeof(msg) - 1,
                             TEST_CONTEXT, sizeof(TEST_CONTEXT) - 1, sk));
    BOOST_CHECK(!mldsa::Sign(sig, &siglen, msg, sizeof(msg) - 1,
                             nullptr, sizeof(TEST_CONTEXT) - 1, sk));
    BOOST_CHECK(!mldsa::Sign(sig, &siglen, msg, sizeof(msg) - 1,
                             TEST_CONTEXT, 0, sk));
    BOOST_CHECK(!mldsa::Sign(sig, &siglen, msg, sizeof(msg) - 1,
                             TEST_CONTEXT, mldsa::MAX_CONTEXT_BYTES + 1, sk));
    BOOST_CHECK(!mldsa::Sign(sig, &siglen, msg, sizeof(msg) - 1,
                             TEST_CONTEXT, sizeof(TEST_CONTEXT) - 1, nullptr));
    BOOST_CHECK(!mldsa::Verify(nullptr, mldsa::SIGNATURE_BYTES, msg, sizeof(msg) - 1,
                               TEST_CONTEXT, sizeof(TEST_CONTEXT) - 1, pk));
    BOOST_CHECK(!mldsa::Verify(sig, mldsa::SIGNATURE_BYTES, nullptr, sizeof(msg) - 1,
                               TEST_CONTEXT, sizeof(TEST_CONTEXT) - 1, pk));
    BOOST_CHECK(!mldsa::Verify(sig, mldsa::SIGNATURE_BYTES, msg, sizeof(msg) - 1,
                               nullptr, sizeof(TEST_CONTEXT) - 1, pk));
    BOOST_CHECK(!mldsa::Verify(sig, mldsa::SIGNATURE_BYTES, msg, sizeof(msg) - 1,
                               TEST_CONTEXT, 0, pk));
    BOOST_CHECK(!mldsa::Verify(sig, mldsa::SIGNATURE_BYTES, msg, sizeof(msg) - 1,
                               TEST_CONTEXT, mldsa::MAX_CONTEXT_BYTES + 1, pk));
    BOOST_CHECK(!mldsa::Verify(sig, mldsa::SIGNATURE_BYTES, msg, sizeof(msg) - 1,
                               TEST_CONTEXT, sizeof(TEST_CONTEXT) - 1, nullptr));
}

BOOST_AUTO_TEST_CASE(deterministic_keygen_does_not_depend_on_global_rng)
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

BOOST_AUTO_TEST_CASE(mldsa_backend_compatibility_kat)
{
    std::array<std::array<unsigned char, mldsa::SEED_BYTES>, 4> seeds{};
    seeds[1].fill(0xff);
    for (size_t i = 0; i < seeds[2].size(); ++i)
        seeds[2][i] = static_cast<unsigned char>(i);
    const std::array<unsigned char, mldsa::SEED_BYTES> walletLikeSeed{{
        0x0c, 0x7e, 0x4e, 0x8f, 0x2d, 0x85, 0x6a, 0x97,
        0x41, 0x73, 0x3b, 0x1f, 0x9b, 0x2b, 0x8d, 0x44,
        0x31, 0xd5, 0x97, 0xee, 0x36, 0xf3, 0x7c, 0x91,
        0xf6, 0x21, 0x0f, 0x74, 0xd7, 0x90, 0x5a, 0x2c
    }};
    seeds[3] = walletLikeSeed;

    static const char* expectedPublicKeyHashes[] = {
        "eb4e7302842153b0fa19e8620739ad258af4929c26dd89079a7ec7d4282208e1",
        "62c4f1b3164db7fa896a3343e900eb3e13c9f76de122020feba37ee063d49ef0",
        "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46",
        "0d2697f8bb6693644aa76ed6aab823c3b89ae28ab4241dd25ba147289c9476b4"
    };
    static const char* expectedSecretKeyHashes[] = {
        "0f9086044d77b6d610c7e92418d9f70a398c69febc7e99f8254aaea98dcfbe77",
        "6433074c5ffc9e0f2b1d68bb3fda84e439da0a2d93f508a101e9b44835f0b22c",
        "04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b",
        "9c9754163be250124d49606b6d5fa2c4a633038792149870a08e7e4f4894bdac"
    };

    std::array<unsigned char, mldsa::PUBLICKEY_BYTES> publicKey{};
    std::array<unsigned char, mldsa::SECRETKEY_BYTES> secretKey{};
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest{};
    for (size_t i = 0; i < seeds.size(); ++i) {
        BOOST_REQUIRE(mldsa::KeyGen(publicKey.data(), secretKey.data(), seeds[i].data()));

        CSHA256().Write(publicKey.data(), publicKey.size()).Finalize(digest.data());
        BOOST_CHECK_EQUAL(HexStr(digest.begin(), digest.end()), expectedPublicKeyHashes[i]);

        CSHA256().Write(secretKey.data(), secretKey.size()).Finalize(digest.data());
        BOOST_CHECK_EQUAL(HexStr(digest.begin(), digest.end()), expectedSecretKeyHashes[i]);
        memory_cleanse(secretKey.data(), secretKey.size());
    }
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
    CPQKey::KeyData raw(secret.begin(), secret.end());

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
    CPQKey::KeyData raw(secret.begin(), secret.end());
    const CPQPubKey wrongPub = other.GetPubKey();

    CPQKey imported;
    BOOST_CHECK(!imported.SetKeyData(raw, wrongPub));
    BOOST_CHECK(!imported.IsValid());
    BOOST_CHECK(!imported.GetPubKey().IsValid());
    BOOST_CHECK(std::all_of(imported.GetKeyData().begin(), imported.GetKeyData().end(),
                            [](unsigned char byte) { return byte == 0; }));

    uint256 hash;
    std::memset(hash.begin(), 0xa5, 32);
    std::vector<unsigned char> signature;
    BOOST_CHECK(!imported.Sign(hash, signature,
                               TEST_CONTEXT, sizeof(TEST_CONTEXT) - 1));
}

BOOST_AUTO_TEST_CASE(import_rejects_wrong_secret_size)
{
    CPQKey key;
    CPQKey pubSource;
    pubSource.MakeNewKey();
    BOOST_REQUIRE(pubSource.IsValid());

    CPQKey::KeyData tooShort(mldsa::SECRETKEY_BYTES - 1, 0);
    CPQKey::KeyData tooLong(mldsa::SECRETKEY_BYTES + 1, 0);

    BOOST_CHECK(!key.SetKeyData(tooShort, pubSource.GetPubKey()));
    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK(!key.SetKeyData(tooLong, pubSource.GetPubKey()));
    BOOST_CHECK(!key.IsValid());
}

BOOST_AUTO_TEST_CASE(failed_reinitialization_cleanses_prior_secret)
{
    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    BOOST_REQUIRE(std::any_of(key.GetKeyData().begin(), key.GetKeyData().end(),
                              [](unsigned char byte) { return byte != 0; }));

    BOOST_CHECK(!key.SetSeed(nullptr));
    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK(!key.GetPubKey().IsValid());
    BOOST_CHECK(std::all_of(key.GetKeyData().begin(), key.GetKeyData().end(),
                            [](unsigned char byte) { return byte == 0; }));
}

BOOST_AUTO_TEST_CASE(witness_v2_active_rules_accept_valid_and_reject_invalid_mldsa)
{
    const Consensus::PQSignatureContext& context = NetworkContext("main");
    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();
    const uint256 witnessProgram = pubkey.GetWitnessProgram();

    CBasicKeyStore keystore;
    BOOST_REQUIRE(keystore.AddPQKeyPubKey(key, pubkey));

    const CAmount amount = 10 * COIN;
    CMutableTransaction funding;
    funding.vout.emplace_back(amount, GetScriptForWitnessV2PQ(witnessProgram));
    const CTransaction fundingTx(funding);

    CMutableTransaction spend;
    spend.vin.emplace_back(COutPoint(fundingTx.GetHash(), 0));
    spend.vout.emplace_back(amount - 1000, CScript() << OP_TRUE);
    BOOST_REQUIRE(SignSignature(keystore, fundingTx, spend, 0, SIGHASH_ALL, context));
    BOOST_REQUIRE_EQUAL(spend.vin[0].scriptWitness.stack.size(), 2U);
    BOOST_REQUIRE_EQUAL(spend.vin[0].scriptWitness.stack[0].size(), mldsa::SIGNATURE_BYTES);
    BOOST_REQUIRE_EQUAL(spend.vin[0].scriptWitness.stack[1].size(), mldsa::PUBLICKEY_BYTES);

    const int unsupportedHashTypes[] = {
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY
    };
    for (int hashType : unsupportedHashTypes) {
        CMutableTransaction unsupportedSpend;
        unsupportedSpend.vin.emplace_back(COutPoint(fundingTx.GetHash(), 0));
        unsupportedSpend.vout.emplace_back(amount - 1000, CScript() << OP_TRUE);
        BOOST_CHECK(!SignSignature(keystore, fundingTx, unsupportedSpend, 0,
                                   hashType, context));
        BOOST_CHECK(unsupportedSpend.vin[0].scriptWitness.IsNull());
    }

    auto verifySpend = [&](const CMutableTransaction& candidate,
                           unsigned int flags,
                           const Consensus::PQSignatureContext& verifyContext,
                           ScriptError& error) {
        const CTransaction tx(candidate);
        return VerifyScript(tx.vin[0].scriptSig,
                            fundingTx.vout[0].scriptPubKey,
                            &tx.vin[0].scriptWitness,
                            flags,
                            TransactionSignatureChecker(&tx, 0, amount, verifyContext),
                            &error);
    };

    const unsigned int preActivationFlags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    const unsigned int activeFlags = preActivationFlags | SCRIPT_VERIFY_PQ_HYBRID;
    ScriptError error = SCRIPT_ERR_UNKNOWN_ERROR;

    BOOST_CHECK(verifySpend(spend, activeFlags, context, error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    BOOST_CHECK(!verifySpend(spend, activeFlags,
                             Consensus::NullPQSignatureContext(), error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_PQ_SIGNATURE_VERIFY_FAILED);

    CMutableTransaction emptyWitness = spend;
    emptyWitness.vin[0].scriptWitness.stack.clear();

    // Before activation, witness-v2 retains normal future-witness consensus
    // semantics. Relay separately rejects newly-created v2 outputs.
    BOOST_CHECK(verifySpend(emptyWitness, preActivationFlags,
                            Consensus::NullPQSignatureContext(), error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    BOOST_CHECK(!verifySpend(emptyWitness, activeFlags, context, error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);

    CMutableTransaction malformedSignature = spend;
    malformedSignature.vin[0].scriptWitness.stack[0][0] ^= 0x01;
    BOOST_CHECK(!verifySpend(malformedSignature, activeFlags, context, error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_PQ_SIGNATURE_VERIFY_FAILED);
}

BOOST_AUTO_TEST_CASE(witness_v2_signatures_are_bound_to_network_context)
{
    const Consensus::PQSignatureContext& mainContext = NetworkContext("main");
    const Consensus::PQSignatureContext& testContext = NetworkContext("test");
    const Consensus::PQSignatureContext& regtestContext = NetworkContext("regtest");
    const Consensus::PQSignatureContext* contexts[] = {
        &mainContext, &testContext, &regtestContext
    };

    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();

    CBasicKeyStore keystore;
    BOOST_REQUIRE(keystore.AddPQKeyPubKey(key, pubkey));

    const CAmount amount = 10 * COIN;
    CMutableTransaction funding;
    funding.vout.emplace_back(amount,
        GetScriptForWitnessV2PQ(pubkey.GetWitnessProgram()));
    const CTransaction fundingTx(funding);
    const unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
                               SCRIPT_VERIFY_PQ_HYBRID;

    for (size_t signingNetwork = 0; signingNetwork < 3; ++signingNetwork) {
        CMutableTransaction spend;
        spend.vin.emplace_back(COutPoint(fundingTx.GetHash(), 0));
        spend.vout.emplace_back(amount - 1000, CScript() << OP_TRUE);
        BOOST_REQUIRE(SignSignature(keystore, fundingTx, spend, 0, SIGHASH_ALL,
                                    *contexts[signingNetwork]));

        const CTransaction tx(spend);
        for (size_t verifyingNetwork = 0; verifyingNetwork < 3; ++verifyingNetwork) {
            ScriptError error = SCRIPT_ERR_UNKNOWN_ERROR;
            const bool accepted = VerifyScript(
                tx.vin[0].scriptSig, fundingTx.vout[0].scriptPubKey,
                &tx.vin[0].scriptWitness, flags,
                TransactionSignatureChecker(&tx, 0, amount,
                                            *contexts[verifyingNetwork]),
                &error);
            BOOST_CHECK_EQUAL(accepted, signingNetwork == verifyingNetwork);
            BOOST_CHECK_EQUAL(error, signingNetwork == verifyingNetwork
                ? SCRIPT_ERR_OK : SCRIPT_ERR_PQ_SIGNATURE_VERIFY_FAILED);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
