// Copyright (c) 2026 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"
#include "pqkey.h"
#include "test/test_raven.h"
#include "util.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <boost/test/unit_test.hpp>

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using PlainPQValue = std::pair<std::pair<CPQPubKey, std::vector<unsigned char>>, uint256>;
using CryptedPQValue = std::pair<CPQPubKey, std::vector<unsigned char>>;

std::vector<unsigned char> RawSecret(const CPQKey& key)
{
    return std::vector<unsigned char>(key.GetKeyData().begin(), key.GetKeyData().end());
}

std::unique_ptr<CWallet> LoadPQWallet(const std::string& filename)
{
    std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
    std::unique_ptr<CWallet> wallet(new CWallet(std::move(dbw)));
    bool firstRun = false;
    if (wallet->LoadWallet(firstRun) != DB_LOAD_OK)
        throw std::runtime_error("failed to load PQ wallet test database");
    return wallet;
}

struct PQWalletDatabaseTestingSetup : public TestingSetup
{
    int64_t oldKeypoolSize;

    PQWalletDatabaseTestingSetup()
        : TestingSetup(CBaseChainParams::REGTEST),
          oldKeypoolSize(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE))
    {
        // WalletTestingSetup uses a mock database. These tests intentionally
        // exercise the actual Berkeley DB persistence, rewrite, and backup paths.
        bitdb.Close();
        bitdb.Reset();
        gArgs.ForceSetArg("-keypool", 1);
    }

    ~PQWalletDatabaseTestingSetup()
    {
        bitdb.Flush(true);
        bitdb.Reset();
        gArgs.ForceSetArg("-keypool", oldKeypoolSize);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_wallet_tests, PQWalletDatabaseTestingSetup)

BOOST_AUTO_TEST_CASE(unencrypted_pq_key_persists_and_reloads)
{
    const std::string filename = "pq-plain-wallet.dat";
    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();
    const uint256 witnessProgram = pubkey.GetWitnessProgram();
    const std::vector<unsigned char> secret = RawSecret(key);

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        {
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->AddPQKeyPubKey(key, pubkey));
        }

        CWalletDBWrapper rawDbw(&bitdb, filename);
        CDB rawDb(rawDbw, "r");
        PlainPQValue plainRecord;
        BOOST_REQUIRE(rawDb.Read(std::make_pair(std::string("pqkey"), witnessProgram), plainRecord));
        BOOST_CHECK(plainRecord.first.first == pubkey);
        BOOST_CHECK(plainRecord.first.second == secret);
        BOOST_CHECK(!rawDb.Exists(std::make_pair(std::string("cpqkey"), witnessProgram)));
    }

    bitdb.Flush(false);

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        CPQKey loaded;
        BOOST_REQUIRE(wallet->GetPQKey(witnessProgram, loaded));
        BOOST_CHECK(loaded.MatchesPubKey(pubkey));
        BOOST_CHECK(RawSecret(loaded) == secret);
    }
}

BOOST_AUTO_TEST_CASE(encrypted_pq_keys_are_ciphertext_only_after_reload_and_backup)
{
    const std::string filename = "pq-encrypted-wallet.dat";
    const std::string backupFilename = "pq-encrypted-wallet-backup.dat";
    const SecureString passphrase("pq-wallet-regression-passphrase");

    CPQKey migratedKey;
    migratedKey.MakeNewKey();
    BOOST_REQUIRE(migratedKey.IsValid());
    const CPQPubKey migratedPubkey = migratedKey.GetPubKey();
    const uint256 migratedProgram = migratedPubkey.GetWitnessProgram();
    const std::vector<unsigned char> migratedSecret = RawSecret(migratedKey);

    CPQKey addedAfterEncryption;
    addedAfterEncryption.MakeNewKey();
    BOOST_REQUIRE(addedAfterEncryption.IsValid());
    const CPQPubKey addedPubkey = addedAfterEncryption.GetPubKey();
    const uint256 addedProgram = addedPubkey.GetWitnessProgram();
    const std::vector<unsigned char> addedSecret = RawSecret(addedAfterEncryption);

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        {
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->AddPQKeyPubKey(migratedKey, migratedPubkey));
        }

        BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
        BOOST_REQUIRE(wallet->Unlock(passphrase));
        {
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->AddPQKeyPubKey(addedAfterEncryption, addedPubkey));
        }

        {
            CWalletDBWrapper rawDbw(&bitdb, filename);
            CDB rawDb(rawDbw, "r");
            for (const auto& expected : {
                    std::make_pair(migratedProgram, migratedSecret),
                    std::make_pair(addedProgram, addedSecret)}) {
                CryptedPQValue cryptedRecord;
                BOOST_REQUIRE(rawDb.Read(
                    std::make_pair(std::string("cpqkey"), expected.first),
                    cryptedRecord));
                BOOST_CHECK(cryptedRecord.second != expected.second);
                BOOST_CHECK(!rawDb.Exists(
                    std::make_pair(std::string("pqkey"), expected.first)));
            }
        }

        BOOST_REQUIRE(wallet->BackupWallet((GetDataDir() / backupFilename).string()));
    }

    bitdb.Flush(false);

    // A binary backup has the same Berkeley DB file ID as its source. Close
    // each handle before opening the other copy in this environment.
    for (const std::string& walletFile : {backupFilename, filename}) {
        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(walletFile);
            BOOST_CHECK(wallet->IsCrypted());
            BOOST_CHECK(wallet->IsLocked());

            CPQKey loaded;
            BOOST_CHECK(!wallet->GetPQKey(migratedProgram, loaded));
            BOOST_REQUIRE(wallet->Unlock(passphrase));

            BOOST_REQUIRE(wallet->GetPQKey(migratedProgram, loaded));
            BOOST_CHECK(loaded.MatchesPubKey(migratedPubkey));
            BOOST_CHECK(RawSecret(loaded) == migratedSecret);

            BOOST_REQUIRE(wallet->GetPQKey(addedProgram, loaded));
            BOOST_CHECK(loaded.MatchesPubKey(addedPubkey));
            BOOST_CHECK(RawSecret(loaded) == addedSecret);
        }
        bitdb.Flush(false);
    }
}

BOOST_AUTO_TEST_SUITE_END()
