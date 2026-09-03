// Copyright (c) 2026 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"
#include "fs.h"
#include "hash.h"
#include "pqkey.h"
#include "test/test_raven.h"
#include "util.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
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

PlainPQValue PlainPQRecord(const CPQPubKey& pubkey, const std::vector<unsigned char>& secret)
{
    std::vector<unsigned char> keyMaterial;
    keyMaterial.reserve(pubkey.size() + secret.size());
    keyMaterial.insert(keyMaterial.end(), pubkey.begin(), pubkey.end());
    keyMaterial.insert(keyMaterial.end(), secret.begin(), secret.end());
    return std::make_pair(std::make_pair(pubkey, secret), Hash(keyMaterial.begin(), keyMaterial.end()));
}

bool FileContainsSecret(const fs::path& path, const std::vector<unsigned char>& secret)
{
    std::ifstream file(path.string(), std::ios::binary);
    if (!file)
        throw std::runtime_error("failed to read PQ wallet test file");
    const std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    const std::string needle(secret.begin(), secret.end());
    return contents.find(needle) != std::string::npos;
}

class FailingPQPersistenceKeyStore : public CCryptoKeyStore
{
public:
    bool EncryptForTest(CKeyingMaterial& masterKey)
    {
        return EncryptKeys(masterKey);
    }

    bool AddCryptedPQKey(const CPQPubKey&, const std::vector<unsigned char>&) override
    {
        return false;
    }
};

class ThrowingPQPersistenceKeyStore : public FailingPQPersistenceKeyStore
{
public:
    bool AddCryptedPQKey(const CPQPubKey&, const std::vector<unsigned char>&) override
    {
        throw std::runtime_error("injected PQ persistence exception");
    }
};

class InspectableCryptoKeyStore : public CCryptoKeyStore
{
public:
    bool EncryptForTest(CKeyingMaterial& masterKey)
    {
        return EncryptKeys(masterKey);
    }

    bool GetCryptedKeyForTest(const CKeyID& keyID, std::vector<unsigned char>& cryptedSecret)
    {
        LOCK(cs_KeyStore);
        const auto it = mapCryptedKeys.find(keyID);
        if (it == mapCryptedKeys.end())
            return false;
        cryptedSecret = it->second.second;
        return true;
    }
};

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

BOOST_AUTO_TEST_CASE(crypted_ecdsa_write_reports_plaintext_erase_failure)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    // A dummy database accepts writes but cannot erase. The encrypted write
    // must not report success when plaintext deletion fails.
    CWalletDBWrapper dummyDbw;
    CWalletDB dummyDb(dummyDbw);
    BOOST_CHECK(!dummyDb.WriteCryptedKey(
        pubkey, std::vector<unsigned char>(48, 0x4d), CKeyMetadata()));
}

BOOST_AUTO_TEST_CASE(crypted_ecdsa_write_failure_rolls_back_wallet_memory)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    const CKeyID keyID = pubkey.GetID();
    CKeyingMaterial masterKey(WALLET_CRYPTO_KEY_SIZE, 0x3a);

    InspectableCryptoKeyStore source;
    BOOST_REQUIRE(source.AddKeyPubKey(key, pubkey));
    BOOST_REQUIRE(source.EncryptForTest(masterKey));
    std::vector<unsigned char> oldCiphertext;
    BOOST_REQUIRE(source.GetCryptedKeyForTest(keyID, oldCiphertext));

    const SecureString passphrase("ecdsa-rollback-passphrase");
    CMasterKey encryptedMasterKey;
    encryptedMasterKey.vchSalt.assign(WALLET_CRYPTO_SALT_SIZE, 0x7c);
    encryptedMasterKey.nDeriveIterations = 25000;
    CCrypter crypter;
    BOOST_REQUIRE(crypter.SetKeyFromPassphrase(
        passphrase, encryptedMasterKey.vchSalt, encryptedMasterKey.nDeriveIterations,
        encryptedMasterKey.nDerivationMethod));
    BOOST_REQUIRE(crypter.Encrypt(masterKey, encryptedMasterKey.vchCryptedKey));

    CWallet wallet;
    wallet.mapMasterKeys[1] = encryptedMasterKey;
    BOOST_REQUIRE(wallet.LoadCryptedKey(pubkey, oldCiphertext));
    BOOST_CHECK(!wallet.AddCryptedKey(pubkey, std::vector<unsigned char>(48, 0x22)));
    BOOST_REQUIRE(wallet.Unlock(passphrase));
    CKey restored;
    BOOST_REQUIRE(wallet.GetKey(keyID, restored));
    BOOST_CHECK(restored.VerifyPubKey(pubkey));

    CWallet firstFailedAdd;
    BOOST_CHECK(!firstFailedAdd.AddCryptedKey(pubkey, oldCiphertext));
    BOOST_CHECK(!firstFailedAdd.IsCrypted());
}

BOOST_AUTO_TEST_CASE(crypted_pq_write_reports_plaintext_erase_failure)
{
    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();

    // A dummy database accepts writes but cannot erase. This isolates the
    // second half of the cpqkey-write/pqkey-erase operation.
    CWalletDBWrapper dummyDbw;
    CWalletDB dummyDb(dummyDbw);
    BOOST_CHECK(!dummyDb.WriteCryptedPQKey(
        pubkey.GetWitnessProgram(), pubkey, std::vector<unsigned char>(32, 0x5a)));
}

BOOST_AUTO_TEST_CASE(crypted_pq_write_failure_rolls_back_wallet_memory)
{
    CPQKey existingKey;
    CPQKey rejectedKey;
    existingKey.MakeNewKey();
    rejectedKey.MakeNewKey();
    BOOST_REQUIRE(existingKey.IsValid());
    BOOST_REQUIRE(rejectedKey.IsValid());
    const CPQPubKey existingPubKey = existingKey.GetPubKey();
    const CPQPubKey rejectedPubKey = rejectedKey.GetPubKey();

    // Seed encrypted mode without persistence, then exercise a normal write
    // through a dummy DB whose plaintext erase deterministically fails.
    CWallet wallet;
    BOOST_REQUIRE(wallet.LoadCryptedPQKey(existingPubKey, std::vector<unsigned char>(32, 0x11)));
    BOOST_CHECK(!wallet.AddCryptedPQKey(rejectedPubKey, std::vector<unsigned char>(32, 0x22)));
    BOOST_CHECK(wallet.HavePQKey(existingPubKey.GetWitnessProgram()));
    BOOST_CHECK(!wallet.HavePQKey(rejectedPubKey.GetWitnessProgram()));
}

BOOST_AUTO_TEST_CASE(resident_plaintext_pq_key_blocks_crypted_mode)
{
    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();

    CCryptoKeyStore keystore;
    BOOST_REQUIRE(keystore.AddPQKeyPubKey(key, pubkey));
    BOOST_CHECK(!keystore.AddCryptedPQKey(pubkey, std::vector<unsigned char>(32, 0xa5)));
    BOOST_CHECK(!keystore.IsCrypted());
    BOOST_CHECK(keystore.HavePQKey(pubkey.GetWitnessProgram()));
}

BOOST_AUTO_TEST_CASE(pq_persistence_failure_rolls_back_in_memory_encryption)
{
    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();
    const std::vector<unsigned char> secret = RawSecret(key);

    FailingPQPersistenceKeyStore keystore;
    BOOST_REQUIRE(keystore.AddPQKeyPubKey(key, pubkey));
    CKeyingMaterial masterKey(WALLET_CRYPTO_KEY_SIZE, 0x42);
    BOOST_CHECK(!keystore.EncryptForTest(masterKey));
    BOOST_CHECK(!keystore.IsCrypted());

    CPQKey restored;
    BOOST_REQUIRE(keystore.GetPQKey(pubkey.GetWitnessProgram(), restored));
    BOOST_CHECK(RawSecret(restored) == secret);
}

BOOST_AUTO_TEST_CASE(pq_persistence_exception_rolls_back_in_memory_encryption)
{
    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();
    const std::vector<unsigned char> secret = RawSecret(key);

    ThrowingPQPersistenceKeyStore keystore;
    BOOST_REQUIRE(keystore.AddPQKeyPubKey(key, pubkey));
    CKeyingMaterial masterKey(WALLET_CRYPTO_KEY_SIZE, 0x24);
    BOOST_CHECK(!keystore.EncryptForTest(masterKey));
    BOOST_CHECK(!keystore.IsCrypted());

    CPQKey restored;
    BOOST_REQUIRE(keystore.GetPQKey(pubkey.GetWitnessProgram(), restored));
    BOOST_CHECK(RawSecret(restored) == secret);
}

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
        BOOST_CHECK(plainRecord == PlainPQRecord(pubkey, secret));
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

BOOST_AUTO_TEST_CASE(oversized_plaintext_pq_record_is_rejected_before_secure_allocation)
{
    const std::string filename = "pq-oversized-secret-wallet.dat";

    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();
    const uint256 witnessProgram = pubkey.GetWitnessProgram();

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
    }
    bitdb.Flush(false);

    // LockedPool rejects a single allocation above its 256-KiB arena. A
    // corrupt record must therefore be rejected from its encoded length,
    // before the secure vector is constructed.
    const std::vector<unsigned char> oversizedSecret(300000, 0x7b);
    {
        CWalletDBWrapper rawDbw(&bitdb, filename);
        CDB rawDb(rawDbw, "r+");
        BOOST_REQUIRE(rawDb.Write(
            std::make_pair(std::string("pqkey"), witnessProgram),
            PlainPQRecord(pubkey, oversizedSecret)));
    }
    bitdb.Flush(false);

    std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
    std::unique_ptr<CWallet> wallet(new CWallet(std::move(dbw)));
    bool firstRun = false;
    BOOST_CHECK_EQUAL(wallet->LoadWallet(firstRun), DB_CORRUPT);
}

BOOST_AUTO_TEST_CASE(encrypted_pq_keys_are_ciphertext_only_after_reload_and_backup)
{
    const std::string filename = "pq-encrypted-wallet.dat";
    const std::string backupFilename = "pq-encrypted-wallet-backup.dat";
    const SecureString passphrase("pq-wallet-regression-passphrase");

    CKey migratedECDSAKey;
    migratedECDSAKey.MakeNewKey(true);
    const CPubKey migratedECDSAPubkey = migratedECDSAKey.GetPubKey();
    BOOST_REQUIRE(migratedECDSAPubkey.IsValid());

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
            BOOST_REQUIRE(wallet->AddKeyPubKey(migratedECDSAKey, migratedECDSAPubkey));
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
            std::vector<unsigned char> cryptedECDSASecret;
            BOOST_REQUIRE(rawDb.Read(
                std::make_pair(std::string("ckey"), migratedECDSAPubkey),
                cryptedECDSASecret));
            BOOST_CHECK(!rawDb.Exists(
                std::make_pair(std::string("key"), migratedECDSAPubkey)));
            BOOST_CHECK(!rawDb.Exists(
                std::make_pair(std::string("wkey"), migratedECDSAPubkey)));

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

    for (const std::string& walletFile : {filename, backupFilename}) {
        BOOST_CHECK(!FileContainsSecret(GetDataDir() / walletFile, migratedSecret));
        BOOST_CHECK(!FileContainsSecret(GetDataDir() / walletFile, addedSecret));
    }

    // A binary backup has the same Berkeley DB file ID as its source. Close
    // each handle before opening the other copy in this environment.
    for (const std::string& walletFile : {backupFilename, filename}) {
        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(walletFile);
            BOOST_CHECK(wallet->IsCrypted());
            BOOST_CHECK(wallet->IsLocked());

            CPQKey loaded;
            CKey loadedECDSA;
            BOOST_CHECK(!wallet->GetKey(migratedECDSAPubkey.GetID(), loadedECDSA));
            BOOST_CHECK(!wallet->GetPQKey(migratedProgram, loaded));
            BOOST_REQUIRE(wallet->Unlock(passphrase));

            BOOST_REQUIRE(wallet->GetKey(migratedECDSAPubkey.GetID(), loadedECDSA));
            BOOST_CHECK(loadedECDSA.VerifyPubKey(migratedECDSAPubkey));

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

BOOST_AUTO_TEST_CASE(mixed_plaintext_and_ciphertext_pq_records_fail_load_and_backup)
{
    const std::string filename = "pq-mixed-wallet.dat";
    const std::string backupFilename = "pq-mixed-wallet-backup.dat";
    const SecureString passphrase("pq-mixed-wallet-passphrase");

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
        BOOST_REQUIRE(wallet->EncryptWallet(passphrase));

        // Recreate the failure state left by a dropped pqkey erase error.
        {
            CWalletDBWrapper rawDbw(&bitdb, filename);
            CDB rawDb(rawDbw, "r+");
            BOOST_REQUIRE(rawDb.Write(
                std::make_pair(std::string("pqkey"), witnessProgram),
                PlainPQRecord(pubkey, secret)));
        }

        BOOST_CHECK(!wallet->BackupWallet((GetDataDir() / backupFilename).string()));
        BOOST_CHECK(!fs::exists(GetDataDir() / backupFilename));
    }

    bitdb.Flush(false);

    std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
    std::unique_ptr<CWallet> wallet(new CWallet(std::move(dbw)));
    bool firstRun = false;
    BOOST_CHECK_EQUAL(wallet->LoadWallet(firstRun), DB_CORRUPT);
}

BOOST_AUTO_TEST_CASE(plaintext_pq_record_with_master_key_fails_load)
{
    const std::string filename = "pq-master-plaintext-wallet.dat";

    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->AddPQKeyPubKey(key, pubkey));
    }
    {
        CWalletDBWrapper rawDbw(&bitdb, filename);
        CDB rawDb(rawDbw, "r+");
        BOOST_REQUIRE(rawDb.Write(
            std::make_pair(std::string("mkey"), 1U), CMasterKey()));
    }

    bitdb.Flush(false);
    std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
    std::unique_ptr<CWallet> wallet(new CWallet(std::move(dbw)));
    bool firstRun = false;
    BOOST_CHECK_EQUAL(wallet->LoadWallet(firstRun), DB_CORRUPT);
}

BOOST_AUTO_TEST_CASE(plaintext_ecdsa_record_with_master_key_fails_load_and_backup)
{
    const std::string filename = "ecdsa-mixed-wallet.dat";
    const std::string backupFilename = "ecdsa-mixed-wallet-backup.dat";
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());
    const std::vector<unsigned char> cryptedSecret(48, 0x6c);

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->AddKeyPubKey(key, pubkey));
    }

    // Construct the failure state independently: encryption metadata exists
    // beside the original plaintext private-key record. Core 4.8.0 accepted
    // this combination because it checked mixed state only for PQ records.
    {
        CWalletDBWrapper rawDbw(&bitdb, filename);
        CDB rawDb(rawDbw, "r+");
        BOOST_REQUIRE(rawDb.Write(
            std::make_pair(std::string("mkey"), 1U), CMasterKey(), false));
        BOOST_CHECK(rawDb.Exists(std::make_pair(std::string("key"), pubkey)));
    }

    {
        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
        std::unique_ptr<CWallet> wallet(new CWallet(std::move(dbw)));
        bool firstRun = false;
        BOOST_CHECK_EQUAL(wallet->LoadWallet(firstRun), DB_CORRUPT);
    }

    {
        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
        CWallet wallet(std::move(dbw));
        BOOST_REQUIRE(wallet.LoadCryptedKey(pubkey, cryptedSecret));
        BOOST_CHECK(!wallet.BackupWallet((GetDataDir() / backupFilename).string()));
        BOOST_CHECK(!fs::exists(GetDataDir() / backupFilename));
    }
}

BOOST_AUTO_TEST_CASE(rewrite_discards_stale_regular_temporary_database)
{
    const std::string filename = "pq-rewrite-stale-wallet.dat";
    const std::string rewriteFilename = filename + ".rewrite";

    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();
    const uint256 witnessProgram = pubkey.GetWitnessProgram();

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->AddPQKeyPubKey(key, pubkey));
    }

    // Model a complete but stale artifact from an earlier failed rewrite.
    // Its automatically-created version key collides with the source copy and
    // made the old DB_NOOVERWRITE loop fail on every retry.
    {
        CWalletDBWrapper staleDbw(&bitdb, rewriteFilename);
        CDB staleDb(staleDbw, "cr+");
        BOOST_REQUIRE(staleDb.Write(std::string("stale-rewrite-record"), 1));
    }
    // Leave the zero-refcount Berkeley DB handle cached. Rewrite must close it
    // before transactionally removing the stale database on every platform.
    BOOST_REQUIRE(fs::is_regular_file(GetDataDir() / rewriteFilename));

    {
        CWalletDBWrapper sourceDbw(&bitdb, filename);
        BOOST_REQUIRE(sourceDbw.Rewrite());
    }
    BOOST_CHECK(!fs::exists(GetDataDir() / rewriteFilename));

    {
        CWalletDBWrapper rawDbw(&bitdb, filename);
        CDB rawDb(rawDbw, "r");
        PlainPQValue plainRecord;
        BOOST_REQUIRE(rawDb.Read(
            std::make_pair(std::string("pqkey"), witnessProgram), plainRecord));
        BOOST_CHECK(!rawDb.Exists(std::string("stale-rewrite-record")));
    }
}

BOOST_AUTO_TEST_CASE(rewrite_namespace_transaction_abort_preserves_source)
{
    const std::string filename = "pq-rewrite-abort-wallet.dat";
    const std::string replacementFilename = filename + ".replacement";
    const std::string missingFilename = filename + ".missing";

    {
        CWalletDBWrapper sourceDbw(&bitdb, filename);
        CDB sourceDb(sourceDbw, "cr+");
        BOOST_REQUIRE(sourceDb.Write(std::string("old-source-record"), 1));

        CWalletDBWrapper replacementDbw(&bitdb, replacementFilename);
        CDB replacementDb(replacementDbw, "cr+");
        BOOST_REQUIRE(replacementDb.Write(std::string("new-replacement-record"), 2));
    }
    bitdb.Flush(false);

    // Exercise the same Berkeley DB namespace primitive used by Rewrite. A
    // failure after the transactional remove must restore the source name.
    DbTxn* txn = bitdb.TxnBegin();
    BOOST_REQUIRE(txn != nullptr);
    BOOST_REQUIRE_EQUAL(bitdb.dbenv->dbremove(txn, filename.c_str(), nullptr, 0), 0);
    BOOST_REQUIRE_NE(
        bitdb.dbenv->dbrename(txn, missingFilename.c_str(), nullptr, filename.c_str(), 0),
        0);
    BOOST_REQUIRE_EQUAL(txn->abort(), 0);

    {
        CWalletDBWrapper sourceDbw(&bitdb, filename);
        CDB sourceDb(sourceDbw, "r");
        int value = 0;
        BOOST_REQUIRE(sourceDb.Read(std::string("old-source-record"), value));
        BOOST_CHECK_EQUAL(value, 1);
        BOOST_CHECK(!sourceDb.Exists(std::string("new-replacement-record")));
    }
}

BOOST_AUTO_TEST_CASE(rewrite_failure_prevents_encryption_success_and_backup)
{
    const std::string filename = "pq-rewrite-failure-wallet.dat";
    const std::string backupFilename = "pq-rewrite-failure-wallet-backup.dat";
    const SecureString passphrase("pq-rewrite-failure-passphrase");

    CPQKey key;
    key.MakeNewKey();
    BOOST_REQUIRE(key.IsValid());
    const CPQPubKey pubkey = key.GetPubKey();
    const std::vector<unsigned char> secret = RawSecret(key);

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        {
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->AddPQKeyPubKey(key, pubkey));
        }

        // CDB::Rewrite creates this path as a database file. A directory at
        // that exact path deterministically injects rewrite failure.
        const fs::path rewritePath = GetDataDir() / (filename + ".rewrite");
        BOOST_REQUIRE(fs::create_directory(rewritePath));
        BOOST_CHECK(!wallet->EncryptWallet(passphrase));
        BOOST_CHECK(wallet->IsCrypted());

        BOOST_CHECK(!wallet->BackupWallet((GetDataDir() / backupFilename).string()));
        BOOST_CHECK(!fs::exists(GetDataDir() / backupFilename));

        BOOST_REQUIRE(fs::remove(rewritePath));
        BOOST_REQUIRE(wallet->BackupWallet((GetDataDir() / backupFilename).string()));
    }

    bitdb.Flush(false);
    BOOST_CHECK(!FileContainsSecret(GetDataDir() / filename, secret));
    BOOST_CHECK(!FileContainsSecret(GetDataDir() / backupFilename, secret));
}

BOOST_AUTO_TEST_SUITE_END()
