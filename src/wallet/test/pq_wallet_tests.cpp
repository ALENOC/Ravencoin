// Copyright (c) 2026 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparamsbase.h"
#include "fs.h"
#include "hash.h"
#include "pqkey.h"
#include "test/test_raven.h"
#include "util.h"
#include "utilstrencodings.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using PlainPQValue = std::pair<std::pair<CPQPubKey, std::vector<unsigned char>>, uint256>;
using CryptedPQValue = std::pair<CPQPubKey, std::vector<unsigned char>>;

const std::string BIP39_TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const std::string BIP39_TEST_PASSPHRASE = "TREZOR";

std::vector<unsigned char> Bip39TestWords()
{
    return std::vector<unsigned char>(BIP39_TEST_MNEMONIC.begin(), BIP39_TEST_MNEMONIC.end());
}

std::vector<unsigned char> Bip39TestPassphrase()
{
    return std::vector<unsigned char>(BIP39_TEST_PASSPHRASE.begin(), BIP39_TEST_PASSPHRASE.end());
}

std::vector<unsigned char> Bip39TestSeed()
{
    // Trezor's independent BIP39 vector for the mnemonic and passphrase above.
    return ParseHex(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
        "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
}

CHDChain Bip44TestChain(CWallet* wallet)
{
    CKey marker;
    marker.MakeNewKey(true);
    CHDChain chain(wallet);
    chain.UseBip44(true);
    chain.seed_id = marker.GetPubKey().GetID();
    return chain;
}

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

class ScopedDBLockTimeout
{
private:
    DbEnv* env;
    db_timeout_t previousLockTimeout;
    db_timeout_t previousTxnTimeout;
    u_int32_t previousDeadlockPolicy;

public:
    explicit ScopedDBLockTimeout(DbEnv* envIn, db_timeout_t timeout)
        : env(envIn), previousLockTimeout(0), previousTxnTimeout(0), previousDeadlockPolicy(0)
    {
        if (!env ||
            env->get_timeout(&previousLockTimeout, DB_SET_LOCK_TIMEOUT) != 0 ||
            env->get_timeout(&previousTxnTimeout, DB_SET_TXN_TIMEOUT) != 0 ||
            env->get_lk_detect(&previousDeadlockPolicy) != 0) {
            throw std::runtime_error("failed to set Berkeley DB lock timeout");
        }

        bool lockTimeoutChanged = false;
        bool txnTimeoutChanged = false;
        if (env->set_timeout(timeout, DB_SET_LOCK_TIMEOUT) == 0) {
            lockTimeoutChanged = true;
            if (env->set_timeout(timeout, DB_SET_TXN_TIMEOUT) == 0) {
                txnTimeoutChanged = true;
                if (env->set_lk_detect(DB_LOCK_YOUNGEST) == 0)
                    return;
            }
        }

        if (txnTimeoutChanged)
            env->set_timeout(previousTxnTimeout, DB_SET_TXN_TIMEOUT);
        if (lockTimeoutChanged)
            env->set_timeout(previousLockTimeout, DB_SET_LOCK_TIMEOUT);
        env->set_lk_detect(previousDeadlockPolicy);
        throw std::runtime_error("failed to set Berkeley DB lock timeout");
    }

    ~ScopedDBLockTimeout()
    {
        if (env) {
            env->set_timeout(previousLockTimeout, DB_SET_LOCK_TIMEOUT);
            env->set_timeout(previousTxnTimeout, DB_SET_TXN_TIMEOUT);
            env->set_lk_detect(previousDeadlockPolicy);
        }
    }
};

class ScopedDBExpiredLockTimeout
{
private:
    DbEnv* env;
    db_timeout_t previousLockTimeout;
    db_timeout_t previousTxnTimeout;
    bool previousTimeNotGranted;

public:
    explicit ScopedDBExpiredLockTimeout(DbEnv* envIn, db_timeout_t timeout)
        : env(envIn), previousLockTimeout(0), previousTxnTimeout(0),
          previousTimeNotGranted(false)
    {
        u_int32_t previousFlags = 0;
        if (!env ||
            env->get_timeout(&previousLockTimeout, DB_SET_LOCK_TIMEOUT) != 0 ||
            env->get_timeout(&previousTxnTimeout, DB_SET_TXN_TIMEOUT) != 0 ||
            env->get_flags(&previousFlags) != 0) {
            throw std::runtime_error("failed to inspect Berkeley DB timeout state");
        }
        previousTimeNotGranted = (previousFlags & DB_TIME_NOTGRANTED) != 0;

        bool lockTimeoutChanged = false;
        bool txnTimeoutChanged = false;
        if (env->set_timeout(timeout, DB_SET_LOCK_TIMEOUT) == 0) {
            lockTimeoutChanged = true;
            if (env->set_timeout(0, DB_SET_TXN_TIMEOUT) == 0) {
                txnTimeoutChanged = true;
                if (env->set_flags(DB_TIME_NOTGRANTED, 1) == 0)
                    return;
            }
        }

        if (txnTimeoutChanged)
            env->set_timeout(previousTxnTimeout, DB_SET_TXN_TIMEOUT);
        if (lockTimeoutChanged)
            env->set_timeout(previousLockTimeout, DB_SET_LOCK_TIMEOUT);
        env->set_flags(DB_TIME_NOTGRANTED, previousTimeNotGranted ? 1 : 0);
        throw std::runtime_error("failed to configure Berkeley DB lock expiration");
    }

    ~ScopedDBExpiredLockTimeout()
    {
        if (env) {
            env->set_timeout(previousLockTimeout, DB_SET_LOCK_TIMEOUT);
            env->set_timeout(previousTxnTimeout, DB_SET_TXN_TIMEOUT);
            env->set_flags(DB_TIME_NOTGRANTED, previousTimeNotGranted ? 1 : 0);
        }
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

BOOST_AUTO_TEST_CASE(bip39_records_are_key_critical)
{
    for (const std::string& type : {
             "hdchain",
             "bip39words", "bip39passphrase", "bip39vchseed",
             "cbip39words", "cbip39passphrase", "cbip39vchseed"}) {
        BOOST_CHECK_MESSAGE(CWalletDB::IsKeyType(type), type);
    }

    const std::vector<unsigned char> words = Bip39TestWords();
    const std::vector<unsigned char> passphrase = Bip39TestPassphrase();
    const std::vector<unsigned char> seed = Bip39TestSeed();
    const std::vector<unsigned char> cryptedSeed(BIP39_CRYPTED_SEED_SIZE, 0x5a);
    const uint256 wordHash = Hash(words.begin(), words.end());
    auto retainedByKeyOnlyRecovery = [](const std::string& type, const auto& value) {
        CWallet dummyWallet;
        CDataStream key(SER_DISK, CLIENT_VERSION);
        CDataStream serializedValue(SER_DISK, CLIENT_VERSION);
        key << type;
        serializedValue << value;
        return CWalletDB::RecoverKeysOnlyFilter(
            &dummyWallet, std::move(key), std::move(serializedValue));
    };
    BOOST_CHECK(retainedByKeyOnlyRecovery(
        "bip39words", std::make_pair(wordHash, words)));
    BOOST_CHECK(retainedByKeyOnlyRecovery("bip39passphrase", passphrase));
    BOOST_CHECK(retainedByKeyOnlyRecovery("bip39vchseed", seed));
    BOOST_CHECK(retainedByKeyOnlyRecovery(
        "cbip39words", std::make_pair(wordHash, std::vector<unsigned char>(96, 0x31))));
    BOOST_CHECK(retainedByKeyOnlyRecovery(
        "cbip39passphrase", std::vector<unsigned char>(32, 0x42)));
    BOOST_CHECK(retainedByKeyOnlyRecovery("cbip39vchseed", cryptedSeed));
}

BOOST_AUTO_TEST_CASE(bip44_key_only_recovery_preserves_derivation_lineage)
{
    const std::string filename = "bip44-key-only-recovery-wallet.dat";
    const std::vector<unsigned char> words = Bip39TestWords();
    const std::vector<unsigned char> passphrase = Bip39TestPassphrase();
    const std::vector<unsigned char> seed = Bip39TestSeed();
    const uint256 wordHash = Hash(words.begin(), words.end());

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        BOOST_REQUIRE(wallet->SetHDChain(Bip44TestChain(wallet.get()), false));
        CWalletDB walletdb(wallet->GetDBHandle());
        BOOST_REQUIRE(walletdb.WriteBip39Words(wordHash, words, false));
        BOOST_REQUIRE(walletdb.WriteBip39Passphrase(passphrase, false));
        BOOST_REQUIRE(walletdb.WriteBip39VchSeed(seed, false));
    }
    bitdb.Flush(false);

    CWallet dummyWallet;
    std::string backupFilename;
    BOOST_REQUIRE(CWalletDB::Recover(
        filename, &dummyWallet, CWalletDB::RecoverKeysOnlyFilter, backupFilename));
    bitdb.Flush(false);

    std::unique_ptr<CWalletDBWrapper> recoveredDbw(new CWalletDBWrapper(&bitdb, filename));
    std::unique_ptr<CWallet> recovered(new CWallet(std::move(recoveredDbw)));
    bool firstRun = true;
    BOOST_REQUIRE_EQUAL(recovered->LoadWallet(firstRun), DB_LOAD_OK);
    BOOST_CHECK(!firstRun);
    uint256 recoveredHash;
    std::vector<unsigned char> recoveredWords;
    std::vector<unsigned char> recoveredPassphrase;
    std::vector<unsigned char> recoveredSeed;
    recovered->GetBip39Data(
        recoveredHash, recoveredWords, recoveredPassphrase, recoveredSeed);
    BOOST_CHECK(recoveredHash == wordHash);
    BOOST_CHECK(recoveredWords == words);
    BOOST_CHECK(recoveredPassphrase == passphrase);
    BOOST_CHECK(recoveredSeed == seed);

    // Independent expected value for regtest path m/44'/1'/0'/0/0.
    const std::vector<unsigned char> expectedBytes = ParseHex(
        "023765b56ecb006a47d775beee38c45a9fe5dbe11d100b2e2ea3c99196dc915a2d");
    const CPubKey expectedFirstExternal(expectedBytes.begin(), expectedBytes.end());
    BOOST_REQUIRE(expectedFirstExternal.IsValid());

    BOOST_REQUIRE(recovered->TopUpKeyPool(1));
    CPubKey recoveredFirstExternal;
    BOOST_REQUIRE(recovered->GetKeyFromPool(recoveredFirstExternal, false));
    BOOST_CHECK(recoveredFirstExternal == expectedFirstExternal);
}

BOOST_AUTO_TEST_CASE(first_run_detection_covers_hd_bip39_master_and_pq_state)
{
    {
        CWallet wallet;
        BOOST_CHECK(wallet.IsFirstRun());
    }
    {
        CWallet wallet;
        BOOST_REQUIRE(wallet.SetHDChain(Bip44TestChain(&wallet), true));
        BOOST_CHECK(!wallet.IsFirstRun());
    }
    {
        CWallet wallet;
        BOOST_REQUIRE(wallet.LoadVchSeed(Bip39TestSeed()));
        BOOST_CHECK(!wallet.IsFirstRun());
    }
    {
        const std::string filename = "first-run-plaintext-pq-wallet.dat";
        CPQKey key;
        key.MakeNewKey();
        BOOST_REQUIRE(key.IsValid());
        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->AddPQKeyPubKey(key, key.GetPubKey()));
        }
        bitdb.Flush(false);
        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
        CWallet wallet(std::move(dbw));
        bool firstRun = true;
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(firstRun), DB_LOAD_OK);
        BOOST_CHECK(!firstRun);
    }
    {
        const std::string filename = "first-run-encrypted-pq-wallet.dat";
        const SecureString passphrase("first-run-encrypted-pq-passphrase");
        CPQKey key;
        key.MakeNewKey();
        BOOST_REQUIRE(key.IsValid());
        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
            {
                LOCK(wallet->cs_wallet);
                BOOST_REQUIRE(wallet->AddPQKeyPubKey(key, key.GetPubKey()));
            }
            BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
        }
        bitdb.Flush(false);
        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
        CWallet wallet(std::move(dbw));
        bool firstRun = true;
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(firstRun), DB_LOAD_OK);
        BOOST_CHECK(wallet.IsCrypted());
        BOOST_CHECK(!firstRun);
    }
    {
        const std::string filename = "first-run-master-only-wallet.dat";
        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
            CWalletDB walletdb(wallet->GetDBHandle());
            BOOST_REQUIRE(walletdb.WriteMasterKey(1U, CMasterKey()));
        }
        bitdb.Flush(false);
        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
        CWallet wallet(std::move(dbw));
        bool firstRun = true;
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(firstRun), DB_LOAD_OK);
        BOOST_CHECK(!firstRun);
    }
    {
        CWallet wallet;
        BOOST_REQUIRE(wallet.LoadCryptedVchSeed(
            std::vector<unsigned char>(BIP39_CRYPTED_SEED_SIZE, 0x63)));
        BOOST_CHECK(!wallet.IsFirstRun());
    }
}

BOOST_AUTO_TEST_CASE(encrypted_bip44_key_only_recovery_preserves_derivation_lineage)
{
    const std::string filename = "bip44-encrypted-key-only-recovery-wallet.dat";
    const SecureString walletPassphrase("bip44-recovery-wallet-passphrase");
    const std::vector<unsigned char> words = Bip39TestWords();
    const std::vector<unsigned char> passphrase = Bip39TestPassphrase();
    const std::vector<unsigned char> seed = Bip39TestSeed();
    const uint256 wordHash = Hash(words.begin(), words.end());

    CKey persistedKey;
    persistedKey.MakeNewKey(true);
    const CPubKey persistedPubKey = persistedKey.GetPubKey();
    BOOST_REQUIRE(persistedPubKey.IsValid());

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        BOOST_REQUIRE(wallet->SetHDChain(Bip44TestChain(wallet.get()), false));
        BOOST_REQUIRE(wallet->LoadWords(wordHash, words));
        BOOST_REQUIRE(wallet->LoadPassphrase(passphrase));
        BOOST_REQUIRE(wallet->LoadVchSeed(seed));
        {
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->AddKeyPubKey(persistedKey, persistedPubKey));
        }
        {
            CWalletDB walletdb(wallet->GetDBHandle());
            BOOST_REQUIRE(walletdb.WriteBip39Words(wordHash, words, false));
            BOOST_REQUIRE(walletdb.WriteBip39Passphrase(passphrase, false));
            BOOST_REQUIRE(walletdb.WriteBip39VchSeed(seed, false));
        }
        BOOST_REQUIRE(wallet->EncryptWallet(walletPassphrase));
    }
    bitdb.Flush(false);

    CWallet dummyWallet;
    std::string backupFilename;
    BOOST_REQUIRE(CWalletDB::Recover(
        filename, &dummyWallet, CWalletDB::RecoverKeysOnlyFilter, backupFilename));
    bitdb.Flush(false);

    std::unique_ptr<CWallet> recovered = LoadPQWallet(filename);
    BOOST_CHECK(recovered->IsCrypted());
    BOOST_CHECK(recovered->IsLocked());
    BOOST_REQUIRE(recovered->Unlock(walletPassphrase));

    CKey loadedKey;
    BOOST_REQUIRE(recovered->GetKey(persistedPubKey.GetID(), loadedKey));
    BOOST_CHECK(loadedKey.VerifyPubKey(persistedPubKey));

    const std::vector<unsigned char> expectedBytes = ParseHex(
        "023765b56ecb006a47d775beee38c45a9fe5dbe11d100b2e2ea3c99196dc915a2d");
    const CPubKey expectedFirstExternal(expectedBytes.begin(), expectedBytes.end());
    BOOST_REQUIRE(expectedFirstExternal.IsValid());
    BOOST_REQUIRE(recovered->TopUpKeyPool(1));
    CPubKey recoveredFirstExternal;
    BOOST_REQUIRE(recovered->GetKeyFromPool(recoveredFirstExternal, false));
    BOOST_CHECK(recoveredFirstExternal == expectedFirstExternal);
}

BOOST_AUTO_TEST_CASE(bip44_encryption_and_backup_are_ciphertext_only)
{
    const SecureString walletPassphrase("bip44-ciphertext-only-passphrase");
    const std::vector<unsigned char> words = Bip39TestWords();
    const std::vector<unsigned char> fullPassphrase = Bip39TestPassphrase();
    const std::vector<unsigned char> seed = Bip39TestSeed();
    const uint256 wordHash = Hash(words.begin(), words.end());

    for (const bool withMnemonicPassphrase : {false, true}) {
        const std::string suffix = withMnemonicPassphrase ? "with-passphrase" : "without-passphrase";
        const std::string filename = "bip44-ciphertext-only-" + suffix + ".dat";
        const std::string backupFilename = "bip44-ciphertext-only-" + suffix + "-backup.dat";
        const std::vector<unsigned char> mnemonicPassphrase =
            withMnemonicPassphrase ? fullPassphrase : std::vector<unsigned char>();

        CKey persistedKey;
        persistedKey.MakeNewKey(true);
        const CPubKey persistedPubKey = persistedKey.GetPubKey();
        BOOST_REQUIRE(persistedPubKey.IsValid());

        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
            BOOST_REQUIRE(wallet->SetHDChain(Bip44TestChain(wallet.get()), false));
            BOOST_REQUIRE(wallet->LoadWords(wordHash, words));
            BOOST_REQUIRE(wallet->LoadPassphrase(mnemonicPassphrase));
            BOOST_REQUIRE(wallet->LoadVchSeed(seed));
            {
                LOCK(wallet->cs_wallet);
                BOOST_REQUIRE(wallet->AddKeyPubKey(persistedKey, persistedPubKey));
            }
            {
                CWalletDB walletdb(wallet->GetDBHandle());
                BOOST_REQUIRE(walletdb.WriteBip39Words(wordHash, words, false));
                if (withMnemonicPassphrase)
                    BOOST_REQUIRE(walletdb.WriteBip39Passphrase(mnemonicPassphrase, false));
                BOOST_REQUIRE(walletdb.WriteBip39VchSeed(seed, false));
            }

            BOOST_REQUIRE(wallet->EncryptWallet(walletPassphrase));
            {
                CWalletDB walletdb(wallet->GetDBHandle(), "r");
                bool hasPlaintextBip39 = true;
                BOOST_REQUIRE(walletdb.HasPlaintextBip39(hasPlaintextBip39));
                BOOST_CHECK(!hasPlaintextBip39);
                std::vector<unsigned char> cryptedSeed;
                BOOST_CHECK(walletdb.ReadBip39VchSeed(cryptedSeed, true));
                BOOST_CHECK(!walletdb.ReadBip39VchSeed(cryptedSeed, false));
                std::vector<unsigned char> cryptedPassphrase;
                BOOST_CHECK_EQUAL(
                    walletdb.ReadBip39Passphrase(cryptedPassphrase, true),
                    withMnemonicPassphrase);
                BOOST_CHECK(!walletdb.ReadBip39Passphrase(cryptedPassphrase, false));
            }
            BOOST_REQUIRE(wallet->BackupWallet((GetDataDir() / backupFilename).string()));
        }
        bitdb.Flush(false);

        std::unique_ptr<CWallet> recovered = LoadPQWallet(backupFilename);
        BOOST_CHECK(recovered->IsCrypted());
        BOOST_CHECK(recovered->IsLocked());
        BOOST_REQUIRE(recovered->Unlock(walletPassphrase));
        uint256 recoveredHash;
        std::vector<unsigned char> recoveredWords;
        std::vector<unsigned char> recoveredPassphrase;
        std::vector<unsigned char> recoveredSeed;
        recovered->GetBip39Data(
            recoveredHash, recoveredWords, recoveredPassphrase, recoveredSeed);
        BOOST_CHECK(recoveredHash == wordHash);
        BOOST_CHECK(recoveredWords == words);
        BOOST_CHECK(recoveredPassphrase == mnemonicPassphrase);
        BOOST_CHECK(recoveredSeed == seed);
        recovered.reset();
        bitdb.Flush(false);
    }
}

BOOST_AUTO_TEST_CASE(mixed_plaintext_and_ciphertext_bip39_records_fail_load_and_backup)
{
    const SecureString walletPassphrase("bip44-mixed-record-passphrase");
    const std::vector<unsigned char> words = Bip39TestWords();
    const std::vector<unsigned char> mnemonicPassphrase = Bip39TestPassphrase();
    const std::vector<unsigned char> seed = Bip39TestSeed();
    const uint256 wordHash = Hash(words.begin(), words.end());

    for (int record = 0; record < 3; ++record) {
        const std::string filename = strprintf("bip44-mixed-record-%d.dat", record);
        const std::string backupFilename = strprintf("bip44-mixed-record-%d-backup.dat", record);
        CKey persistedKey;
        persistedKey.MakeNewKey(true);

        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
            BOOST_REQUIRE(wallet->SetHDChain(Bip44TestChain(wallet.get()), false));
            BOOST_REQUIRE(wallet->LoadWords(wordHash, words));
            BOOST_REQUIRE(wallet->LoadPassphrase(mnemonicPassphrase));
            BOOST_REQUIRE(wallet->LoadVchSeed(seed));
            {
                LOCK(wallet->cs_wallet);
                BOOST_REQUIRE(wallet->AddKeyPubKey(persistedKey, persistedKey.GetPubKey()));
            }
            {
                CWalletDB walletdb(wallet->GetDBHandle());
                BOOST_REQUIRE(walletdb.WriteBip39Words(wordHash, words, false));
                BOOST_REQUIRE(walletdb.WriteBip39Passphrase(mnemonicPassphrase, false));
                BOOST_REQUIRE(walletdb.WriteBip39VchSeed(seed, false));
            }
            BOOST_REQUIRE(wallet->EncryptWallet(walletPassphrase));

            {
                CWalletDB walletdb(wallet->GetDBHandle());
                if (record == 0)
                    BOOST_REQUIRE(walletdb.WriteBip39Words(wordHash, words, false));
                else if (record == 1)
                    BOOST_REQUIRE(walletdb.WriteBip39Passphrase(mnemonicPassphrase, false));
                else
                    BOOST_REQUIRE(walletdb.WriteBip39VchSeed(seed, false));

                bool hasPlaintextBip39 = false;
                BOOST_REQUIRE(walletdb.HasPlaintextBip39(hasPlaintextBip39));
                BOOST_CHECK(hasPlaintextBip39);
            }
            BOOST_CHECK(!wallet->BackupWallet((GetDataDir() / backupFilename).string()));
            BOOST_CHECK(!fs::exists(GetDataDir() / backupFilename));
        }
        bitdb.Flush(false);

        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
        CWallet wallet(std::move(dbw));
        bool firstRun = false;
        BOOST_CHECK_EQUAL(wallet.LoadWallet(firstRun), DB_CORRUPT);
        bitdb.Flush(false);
    }
}

BOOST_AUTO_TEST_CASE(bip39_plaintext_erase_errors_abort_encryption)
{
    const SecureString walletPassphrase("bip39-erase-failure-passphrase");
    const std::vector<unsigned char> words = Bip39TestWords();
    const std::vector<unsigned char> mnemonicPassphrase = Bip39TestPassphrase();
    const std::vector<unsigned char> seed = Bip39TestSeed();
    const uint256 wordHash = Hash(words.begin(), words.end());

    for (int target = 0; target < 3; ++target) {
        const std::string filename = strprintf("bip39-erase-failure-%d.dat", target);
        const std::string targetType = target == 0 ? "bip39words" :
                                       target == 1 ? "bip39passphrase" :
                                                     "bip39vchseed";
        CKey persistedKey;
        persistedKey.MakeNewKey(true);
        const CPubKey persistedPubKey = persistedKey.GetPubKey();
        BOOST_REQUIRE(persistedPubKey.IsValid());

        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
            BOOST_REQUIRE(wallet->SetHDChain(Bip44TestChain(wallet.get()), false));
            BOOST_REQUIRE(wallet->LoadWords(wordHash, words));
            BOOST_REQUIRE(wallet->LoadPassphrase(mnemonicPassphrase));
            BOOST_REQUIRE(wallet->LoadVchSeed(seed));
            {
                LOCK(wallet->cs_wallet);
                BOOST_REQUIRE(wallet->AddKeyPubKey(persistedKey, persistedPubKey));
            }
            {
                CWalletDB walletdb(wallet->GetDBHandle());
                // Earlier erases are deliberately DB_NOTFOUND in the later
                // cases, so the failing operation is unambiguous.
                if (target == 0)
                    BOOST_REQUIRE(walletdb.WriteBip39Words(wordHash, words, false));
                if (target <= 1)
                    BOOST_REQUIRE(walletdb.WriteBip39Passphrase(mnemonicPassphrase, false));
                BOOST_REQUIRE(walletdb.WriteBip39VchSeed(seed, false));
            }
            {
                // Berkeley DB orders serialized string keys by their encoded
                // length first. Fill leaves on both sides of the target length
                // so mkey/ckey writes do not collide with the blocked page.
                CDB filler(wallet->GetDBHandle(), "r+");
                BOOST_REQUIRE(filler.TxnBegin());
                const std::vector<unsigned char> padding(256, 0x39);
                for (int i = 0; i < 512; ++i) {
                    const std::string suffix = strprintf("%04d", i);
                    std::string lower(targetType.size(), 'a');
                    std::string upper(targetType.size(), 'z');
                    lower.replace(lower.size() - suffix.size(), suffix.size(), suffix);
                    upper.replace(upper.size() - suffix.size(), suffix.size(), suffix);
                    BOOST_REQUIRE(filler.Write(lower, padding));
                    BOOST_REQUIRE(filler.Write(upper, padding));
                }
                BOOST_REQUIRE(filler.TxnCommit());
            }

            ScopedDBExpiredLockTimeout timeout(bitdb.dbenv, 100000);
            std::atomic<bool> blockerReady{false};
            std::atomic<bool> releaseBlocker{false};
            std::atomic<bool> blockerWriteSucceeded{false};
            std::atomic<bool> blockerAbortSucceeded{false};
            std::thread blockerThread([&] {
                try {
                    CWalletDB blocker(wallet->GetDBHandle());
                    if (blocker.TxnBegin()) {
                        bool wrote = false;
                        if (target == 0)
                            wrote = blocker.WriteBip39Words(
                                wordHash, std::vector<unsigned char>(words.size(), 0x71), false);
                        else if (target == 1)
                            wrote = blocker.WriteBip39Passphrase(
                                std::vector<unsigned char>(mnemonicPassphrase.size(), 0x72), false);
                        else
                            wrote = blocker.WriteBip39VchSeed(
                                std::vector<unsigned char>(seed.size(), 0x73), false);
                        blockerWriteSucceeded = wrote;
                        blockerReady = true;
                        for (int i = 0; i < 2000 && !releaseBlocker; ++i)
                            std::this_thread::sleep_for(std::chrono::milliseconds(5));
                        blockerAbortSucceeded = blocker.TxnAbort();
                        return;
                    }
                } catch (...) {
                }
                blockerReady = true;
            });

            for (int i = 0; i < 1000 && !blockerReady; ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            if (!blockerReady || !blockerWriteSucceeded) {
                releaseBlocker = true;
                blockerThread.join();
                BOOST_FAIL("failed to establish Berkeley DB record blocker");
            }

            std::atomic<bool> timeoutObserved{false};
            std::atomic<bool> detectorFailed{false};
            std::thread detectorThread([&] {
                for (int i = 0; i < 1000; ++i) {
                    int rejected = 0;
                    if (bitdb.dbenv->lock_detect(0, DB_LOCK_EXPIRE, &rejected) != 0) {
                        detectorFailed = true;
                        break;
                    }
                    if (rejected > 0) {
                        timeoutObserved = true;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
                releaseBlocker = true;
            });

            const bool encrypted = wallet->EncryptWallet(walletPassphrase);
            detectorThread.join();
            releaseBlocker = true;
            blockerThread.join();

            BOOST_CHECK(!detectorFailed);
            BOOST_CHECK(timeoutObserved);
            BOOST_CHECK(blockerAbortSucceeded);
            BOOST_CHECK(!encrypted);
            BOOST_CHECK(wallet->IsCrypted());
            BOOST_CHECK(wallet->IsLocked());
        }
        bitdb.Flush(false);

        CWalletDBWrapper rawDbw(&bitdb, filename);
        CDB rawDb(rawDbw, "r");
        BOOST_CHECK(rawDb.Exists(targetType));
        BOOST_CHECK(!rawDb.Exists(std::make_pair(std::string("mkey"), 1U)));
        BOOST_CHECK(!rawDb.Exists(std::make_pair(std::string("ckey"), persistedPubKey)));
        BOOST_CHECK(!rawDb.Exists(std::string("cbip39words")));
        BOOST_CHECK(!rawDb.Exists(std::string("cbip39passphrase")));
        BOOST_CHECK(!rawDb.Exists(std::string("cbip39vchseed")));
    }
}

BOOST_AUTO_TEST_CASE(bip44_incomplete_or_malformed_seed_fails_load)
{
    const std::vector<unsigned char> words = Bip39TestWords();
    const uint256 wordHash = Hash(words.begin(), words.end());
    const std::vector<unsigned char> validSeed = Bip39TestSeed();

    auto expectCorrupt = [&](const std::string& suffix, bool writeWords,
                             bool writeSeed, const std::vector<unsigned char>& seed) {
        const std::string filename = "bip44-incomplete-" + suffix + ".dat";
        {
            std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
            BOOST_REQUIRE(wallet->SetHDChain(Bip44TestChain(wallet.get()), false));
            CWalletDB walletdb(wallet->GetDBHandle());
            if (writeWords)
                BOOST_REQUIRE(walletdb.WriteBip39Words(wordHash, words, false));
            if (writeSeed)
                BOOST_REQUIRE(walletdb.WriteBip39VchSeed(seed, false));
        }
        bitdb.Flush(false);

        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, filename));
        std::unique_ptr<CWallet> wallet(new CWallet(std::move(dbw)));
        bool firstRun = false;
        BOOST_CHECK_EQUAL(wallet->LoadWallet(firstRun), DB_CORRUPT);
        wallet.reset();
        bitdb.Flush(false);
    };

    expectCorrupt("no-bip39", false, false, {});
    expectCorrupt("words-only", true, false, {});
    expectCorrupt("seed-only", false, true, validSeed);
    expectCorrupt("empty-seed", true, true, {});
    expectCorrupt("short-seed", true, true, std::vector<unsigned char>(63, 0x11));
    expectCorrupt("long-seed", true, true, std::vector<unsigned char>(65, 0x22));
}

BOOST_AUTO_TEST_CASE(bip44_derivation_refuses_missing_seed_without_advancing_counter)
{
    const std::string filename = "bip44-missing-seed-derivation-wallet.dat";
    std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
    BOOST_REQUIRE(wallet->SetHDChain(Bip44TestChain(wallet.get()), false));
    BOOST_CHECK_EQUAL(wallet->GetHDChain().nExternalChainCounter, 0U);
    BOOST_CHECK_EQUAL(wallet->GetHDChain().nInternalChainCounter, 0U);

    BOOST_CHECK_THROW(wallet->TopUpKeyPool(1), std::runtime_error);
    BOOST_CHECK_EQUAL(wallet->GetHDChain().nExternalChainCounter, 0U);
    BOOST_CHECK_EQUAL(wallet->GetHDChain().nInternalChainCounter, 0U);
    BOOST_CHECK(wallet->GetKeys().empty());

    const std::vector<unsigned char> words = Bip39TestWords();
    const std::vector<unsigned char> seed = Bip39TestSeed();
    BOOST_REQUIRE(wallet->LoadWords(Hash(words.begin(), words.end()), words));
    BOOST_REQUIRE(wallet->LoadVchSeed(seed));
    BOOST_REQUIRE(wallet->TopUpKeyPool(1));
    CWalletDB walletdb(wallet->GetDBHandle());
    CKeyPool firstPoolEntry;
    CKeyPool internalPoolEntry;
    CKeyPool skippedPoolEntry;
    BOOST_CHECK(walletdb.ReadPool(1, firstPoolEntry));
    BOOST_CHECK(walletdb.ReadPool(2, internalPoolEntry));
    BOOST_CHECK(!walletdb.ReadPool(3, skippedPoolEntry));
}

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

BOOST_AUTO_TEST_CASE(bip44_encryption_write_failure_returns_and_aborts)
{
    const std::string filename = "bip44-write-failure-wallet.dat";
    const SecureString passphrase("bip44-write-failure-passphrase");
    const std::vector<unsigned char> words = Bip39TestWords();
    const std::vector<unsigned char> mnemonicPassphrase = Bip39TestPassphrase();
    const std::vector<unsigned char> seed = Bip39TestSeed();
    const uint256 wordHash = Hash(words.begin(), words.end());

    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());

    {
        std::unique_ptr<CWallet> wallet = LoadPQWallet(filename);
        BOOST_REQUIRE(wallet->SetHDChain(Bip44TestChain(wallet.get()), false));
        BOOST_REQUIRE(wallet->LoadWords(wordHash, words));
        BOOST_REQUIRE(wallet->LoadPassphrase(mnemonicPassphrase));
        BOOST_REQUIRE(wallet->LoadVchSeed(seed));
        {
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->AddKeyPubKey(key, pubkey));
        }
        {
            CWalletDB walletdb(wallet->GetDBHandle());
            BOOST_REQUIRE(walletdb.WriteBip39Words(wordHash, words, false));
            BOOST_REQUIRE(walletdb.WriteBip39Passphrase(mnemonicPassphrase, false));
            BOOST_REQUIRE(walletdb.WriteBip39VchSeed(seed, false));
        }
        {
            // Berkeley DB locks B-tree pages, not just logical records. Place
            // the encrypted BIP39 key on leaves well separated from the
            // short mkey/ckey keys so the blocker cannot stop encryption
            // before the live keystore has mutated.
            CDB filler(wallet->GetDBHandle(), "r+");
            BOOST_REQUIRE(filler.TxnBegin());
            const std::vector<unsigned char> padding(256, 0x31);
            for (int i = 0; i < 512; ++i) {
                BOOST_REQUIRE(filler.Write(strprintf("cbip39v%04d", i), padding));
                BOOST_REQUIRE(filler.Write(strprintf("cbip39x%04d", i), padding));
            }
            BOOST_REQUIRE(filler.TxnCommit());
        }

        // Hold the encrypted-word key in a second transaction. EncryptWallet
        // reaches this write only after EncryptKeys has replaced the live
        // plaintext key map. The fixed path must return through one cleanup,
        // not assert or continue through a freed CWalletDB pointer.
        {
            ScopedDBLockTimeout timeout(bitdb.dbenv, 5000000);
            CWalletDB blocker(wallet->GetDBHandle());
            BOOST_REQUIRE(blocker.TxnBegin());
            BOOST_REQUIRE(blocker.WriteBip39Words(
                wordHash, std::vector<unsigned char>(32, 0xa7), true));
            std::atomic<bool> cycleAttempted{false};
            std::atomic<bool> cycleResolved{false};
            std::atomic<bool> blockerWriteSucceeded{false};
            std::thread cycleThread([&blocker, &blockerWriteSucceeded, &cycleAttempted,
                                     &cycleResolved, &wallet] {
                // IsCrypted becomes true only after EncryptKeys has replaced
                // the live maps and the younger transaction owns mkey/ckey.
                for (int attempt = 0; attempt < 500; ++attempt) {
                    if (wallet->IsCrypted()) {
                        cycleAttempted = true;
                        blockerWriteSucceeded = blocker.WriteMasterKey(1U, CMasterKey());
                        cycleResolved = true;
                        return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            });
            std::thread detectorThread([&cycleAttempted, &cycleResolved] {
                for (int attempt = 0; attempt < 500 && !cycleAttempted; ++attempt)
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                for (int attempt = 0; attempt < 50 && !cycleResolved; ++attempt) {
                    int aborted = 0;
                    bitdb.dbenv->lock_detect(0, DB_LOCK_YOUNGEST, &aborted);
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            });
            const bool encrypted = wallet->EncryptWallet(passphrase);
            cycleThread.join();
            detectorThread.join();
            BOOST_CHECK(!encrypted);
            BOOST_CHECK(cycleAttempted);
            BOOST_CHECK(cycleResolved);
            BOOST_CHECK(blockerWriteSucceeded);
            BOOST_CHECK(wallet->IsCrypted());
            BOOST_CHECK(wallet->IsLocked());
            BOOST_REQUIRE(blocker.TxnAbort());
        }
    }

    bitdb.Flush(false);

    // The failed encryption transaction must leave the original on-disk
    // wallet intact and plaintext; restart reconstructs its exact key and
    // deterministic-seed inputs.
    std::unique_ptr<CWallet> reloaded = LoadPQWallet(filename);
    BOOST_CHECK(!reloaded->IsCrypted());
    CKey loadedKey;
    BOOST_REQUIRE(reloaded->GetKey(pubkey.GetID(), loadedKey));
    BOOST_CHECK(loadedKey.VerifyPubKey(pubkey));
    uint256 loadedHash;
    std::vector<unsigned char> loadedWords;
    std::vector<unsigned char> loadedPassphrase;
    std::vector<unsigned char> loadedSeed;
    reloaded->GetBip39Data(loadedHash, loadedWords, loadedPassphrase, loadedSeed);
    BOOST_CHECK(loadedHash == wordHash);
    BOOST_CHECK(loadedWords == words);
    BOOST_CHECK(loadedPassphrase == mnemonicPassphrase);
    BOOST_CHECK(loadedSeed == seed);
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
