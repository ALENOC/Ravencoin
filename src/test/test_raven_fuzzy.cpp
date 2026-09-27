// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/raven-config.h"
#endif

#include "consensus/merkle.h"
#include "chainparams.h"
#include "crypto/mldsa.h"
#include "primitives/block.h"
#include "pqkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "addrman.h"
#include "chain.h"
#include "coins.h"
#include "compressor.h"
#include "net.h"
#include "protocol.h"
#include "streams.h"
#include "undo.h"
#include "version.h"
#include "pubkey.h"

#include <stdint.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

namespace {

// The newline permits a readable, tracked AFL seed file. Other test IDs keep
// their historical binary format.
static const unsigned char PQ_FUZZ_MAGIC[] = "PQFZ\n";
static const CAmount PQ_FUZZ_AMOUNT = 10000;
static const unsigned int PQ_FUZZ_FLAGS = SCRIPT_VERIFY_P2SH |
                                           SCRIPT_VERIFY_WITNESS |
                                           SCRIPT_VERIFY_PQ_HYBRID;
static volatile bool pqFuzzResult;

struct PQFuzzFixture {
    std::array<Consensus::PQSignatureContext, 3> contexts;
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> signature;

    PQFuzzFixture()
    {
        const char* networks[] = {"main", "test", "regtest"};
        for (size_t i = 0; i < contexts.size(); ++i) {
            const std::unique_ptr<CChainParams> params = CreateChainParams(networks[i]);
            if (!params)
                std::abort();
            contexts[i] = params->GetConsensus().pqSignatureContext;
        }

        // The test seed is public. CPQKey holds and cleanses the private key;
        // only a valid public key and randomized signature survive setup.
        const std::array<unsigned char, mldsa::SEED_BYTES> seed{};
        CPQKey key;
        if (!key.SetSeed(seed.data()))
            std::abort();
        pubkey = key.GetPubKey().GetVch();

        CMutableTransaction spend;
        spend.vin.emplace_back(COutPoint(uint256(), 0));
        spend.vout.emplace_back(PQ_FUZZ_AMOUNT - 1000, CScript() << OP_TRUE);
        const CTransaction tx(spend);
        const uint256 sighash = SignatureHash(CScript(), tx, 0, SIGHASH_ALL,
                                               PQ_FUZZ_AMOUNT,
                                               SIGVERSION_WITNESS_V2_PQ);
        if (!key.Sign(sighash, signature, contexts[0].data(), contexts[0].size()))
            std::abort();
    }
};

const PQFuzzFixture& GetPQFuzzFixture()
{
    static const PQFuzzFixture fixture;
    return fixture;
}

bool FuzzPQWitness(const uint8_t* input, size_t size)
{
    const PQFuzzFixture& fixture = GetPQFuzzFixture();
    const uint8_t mode = size ? input[0] : 0;
    const uint8_t* payload = size ? input + 1 : input;
    const size_t payloadSize = size ? size - 1 : 0;
    const uint8_t first = payloadSize ? payload[0] : 0;

    CMutableTransaction spend;
    spend.vin.emplace_back(COutPoint(uint256(), 0));
    spend.vout.emplace_back(PQ_FUZZ_AMOUNT - 1000, CScript() << OP_TRUE);
    spend.vin[0].scriptWitness.stack.push_back(fixture.signature);
    spend.vin[0].scriptWitness.stack.push_back(fixture.pubkey);
    std::vector<unsigned char>& signature = spend.vin[0].scriptWitness.stack[0];
    std::vector<unsigned char>& pubkey = spend.vin[0].scriptWitness.stack[1];

    // Preserve exact sizes for these byte mutations, so malformed ML-DSA
    // signatures and public keys reach the actual liboqs verifier.
    if (mode & 0x01) {
        if (payloadSize == 0)
            signature[0] ^= 1;
        for (size_t i = 0; i < std::min(payloadSize, signature.size()); ++i)
            signature[(first + i) % signature.size()] ^= payload[i];
    }
    if (mode & 0x02) {
        if (payloadSize == 0)
            pubkey[0] ^= 1;
        for (size_t i = 0; i < std::min(payloadSize, pubkey.size()); ++i)
            pubkey[(first + i) % pubkey.size()] ^= payload[i];
    }

    // Bind the program to even a mutated key by default. The mismatch mode
    // then tests the cheap hash check before expensive verification.
    uint256 program = CPQPubKey(pubkey).GetWitnessProgram();
    CScript scriptPubKey = GetScriptForWitnessV2PQ(program);
    if (mode & 0x04) {
        if ((first % 3) == 1) {
            std::vector<unsigned char> shortProgram(program.begin(), program.end() - 1);
            scriptPubKey = CScript() << OP_2 << shortProgram;
        } else if ((first % 3) == 2) {
            std::vector<unsigned char> longProgram(program.begin(), program.end());
            longProgram.push_back(first);
            scriptPubKey = CScript() << OP_2 << longProgram;
        } else {
            program.begin()[0] ^= 1;
            scriptPubKey = GetScriptForWitnessV2PQ(program);
        }
    }
    if (mode & 0x08) {
        switch (first % 6) {
        case 0: spend.vin[0].scriptWitness.stack.resize(1); break;
        case 1: spend.vin[0].scriptWitness.stack.emplace_back(1, first); break;
        case 2: signature.pop_back(); break;
        case 3: signature.push_back(first); break;
        case 4: pubkey.pop_back(); break;
        case 5: pubkey.push_back(first); break;
        }
    }
    if (mode & 0x10) {
        spend.nVersion ^= 1 + first;
        spend.nLockTime ^= payloadSize > 1 ? payload[1] : 1;
        spend.vin[0].nSequence ^= payloadSize > 2 ? payload[2] : 1;
        spend.vout[0].nValue += payloadSize > 3 ? payload[3] : 1;
    }
    if (mode & 0x40) {
        const size_t scriptSize = std::min(payloadSize, size_t(100));
        spend.vin[0].scriptSig = scriptSize
            ? CScript(payload, payload + scriptSize) : CScript() << OP_TRUE;
    }
    if (mode & 0x80)
        scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(program.begin(), program.end());

    const Consensus::PQSignatureContext& context = fixture.contexts[(mode & 0x20)
        ? 1 + (first % 2) : 0];
    const CTransaction tx(spend);
    ScriptError error = SCRIPT_ERR_UNKNOWN_ERROR;
    return VerifyScript(tx.vin[0].scriptSig, scriptPubKey,
                        &tx.vin[0].scriptWitness, PQ_FUZZ_FLAGS,
                        TransactionSignatureChecker(&tx, 0, PQ_FUZZ_AMOUNT, context),
                        &error);
}

} // namespace

enum TEST_ID
{
    CBLOCK_DESERIALIZE = 0,
    CTRANSACTION_DESERIALIZE,
    CBLOCKLOCATOR_DESERIALIZE,
    CBLOCKMERKLEROOT,
    CADDRMAN_DESERIALIZE,
    CBLOCKHEADER_DESERIALIZE,
    CBANENTRY_DESERIALIZE,
    CTXUNDO_DESERIALIZE,
    CBLOCKUNDO_DESERIALIZE,
    CCOINS_DESERIALIZE,
    CNETADDR_DESERIALIZE,
    CSERVICE_DESERIALIZE,
    CMESSAGEHEADER_DESERIALIZE,
    CADDRESS_DESERIALIZE,
    CINV_DESERIALIZE,
    CBLOOMFILTER_DESERIALIZE,
    CDISKBLOCKINDEX_DESERIALIZE,
    CTXOUTCOMPRESSOR_DESERIALIZE,
    TEST_ID_END
};

bool read_stdin(std::vector<uint8_t> &data)
{
    uint8_t buffer[1024];
    ssize_t length = 0;
    while ((length = read(STDIN_FILENO, buffer, 1024)) > 0)
    {
        data.insert(data.end(), buffer, buffer + length);

        if (data.size() > (1 << 20)) return false;
    }
    return length == 0;
}

int test_one_input(std::vector<uint8_t> buffer)
{
    if (buffer.size() >= sizeof(PQ_FUZZ_MAGIC) - 1 &&
        std::memcmp(buffer.data(), PQ_FUZZ_MAGIC, sizeof(PQ_FUZZ_MAGIC) - 1) == 0) {
        pqFuzzResult = FuzzPQWitness(buffer.data() + sizeof(PQ_FUZZ_MAGIC) - 1,
                                     buffer.size() - (sizeof(PQ_FUZZ_MAGIC) - 1));
        return 0;
    }

    if (buffer.size() < sizeof(uint32_t)) return 0;

    uint32_t test_id = 0xffffffff;
    memcpy(&test_id, buffer.data(), sizeof(uint32_t));
    buffer.erase(buffer.begin(), buffer.begin() + sizeof(uint32_t));

    if (test_id >= TEST_ID_END) return 0;

    CDataStream ds(buffer, SER_NETWORK, INIT_PROTO_VERSION);
    try
    {
        int nVersion;
        ds >> nVersion;
        ds.SetVersion(nVersion);
    } catch (const std::ios_base::failure &e)
    {
        return 0;
    }

    switch (test_id)
    {
        case CBLOCK_DESERIALIZE:
        {
            try
            {
                CBlock block;
                ds >> block;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CTRANSACTION_DESERIALIZE:
        {
            try
            {
                CTransaction tx(deserialize, ds);
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CBLOCKLOCATOR_DESERIALIZE:
        {
            try
            {
                CBlockLocator bl;
                ds >> bl;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CBLOCKMERKLEROOT:
        {
            try
            {
                CBlock block;
                ds >> block;
                bool mutated;
                BlockMerkleRoot(block, &mutated);
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CADDRMAN_DESERIALIZE:
        {
            try
            {
                CAddrMan am;
                ds >> am;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CBLOCKHEADER_DESERIALIZE:
        {
            try
            {
                CBlockHeader bh;
                ds >> bh;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CBANENTRY_DESERIALIZE:
        {
            try
            {
                CBanEntry be;
                ds >> be;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CTXUNDO_DESERIALIZE:
        {
            try
            {
                CTxUndo tu;
                ds >> tu;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CBLOCKUNDO_DESERIALIZE:
        {
            try
            {
                CBlockUndo bu;
                ds >> bu;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CCOINS_DESERIALIZE:
        {
            try
            {
                Coin coin;
                ds >> coin;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CNETADDR_DESERIALIZE:
        {
            try
            {
                CNetAddr na;
                ds >> na;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CSERVICE_DESERIALIZE:
        {
            try
            {
                CService s;
                ds >> s;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CMESSAGEHEADER_DESERIALIZE:
        {
            CMessageHeader::MessageStartChars pchMessageStart = {0x00, 0x00, 0x00, 0x00};
            try
            {
                CMessageHeader mh(pchMessageStart);
                ds >> mh;
                if (!mh.IsValid(pchMessageStart))
                { return 0; }
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CADDRESS_DESERIALIZE:
        {
            try
            {
                CAddress a;
                ds >> a;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CINV_DESERIALIZE:
        {
            try
            {
                CInv i;
                ds >> i;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CBLOOMFILTER_DESERIALIZE:
        {
            try
            {
                CBloomFilter bf;
                ds >> bf;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CDISKBLOCKINDEX_DESERIALIZE:
        {
            try
            {
                CDiskBlockIndex dbi;
                ds >> dbi;
            } catch (const std::ios_base::failure &e)
            { return 0; }
            break;
        }
        case CTXOUTCOMPRESSOR_DESERIALIZE:
        {
            CTxOut to;
            CTxOutCompressor toc(to);
            try
            {
                ds >> toc;
            } catch (const std::ios_base::failure &e)
            { return 0; }

            break;
        }
        default:
            return 0;
    }
    return 0;
}

static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;

void initialize()
{
    globalVerifyHandle = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
}

// This function is used by libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > (1 << 20))
        return 0;
    test_one_input(std::vector<uint8_t>(data, data + size));
    return 0;
}

// This function is used by libFuzzer
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    initialize();
    return 0;
}

// Disabled under WIN32 due to clash with Cygwin's WinMain.
#ifndef WIN32

// Declare main(...) "weak" to allow for libFuzzer linking. libFuzzer provides
// the main(...) function.
__attribute__((weak))
#endif
int main(int argc, char **argv)
{
    initialize();
    if (argc == 2 && std::strcmp(argv[1], "--pq-smoke") == 0) {
        const uint8_t badSignature[] = {0x01};
        const uint8_t badPubkey[] = {0x02};
        const uint8_t badProgram[] = {0x04};
        const uint8_t badStack[] = {0x08};
        const uint8_t badTransaction[] = {0x10};
        const uint8_t wrongNetwork[] = {0x20};
        const uint8_t badScriptSig[] = {0x40};
        const bool expectedResults = FuzzPQWitness(nullptr, 0) &&
            !FuzzPQWitness(badSignature, sizeof(badSignature)) &&
            !FuzzPQWitness(badPubkey, sizeof(badPubkey)) &&
            !FuzzPQWitness(badProgram, sizeof(badProgram)) &&
            !FuzzPQWitness(badStack, sizeof(badStack)) &&
            !FuzzPQWitness(badTransaction, sizeof(badTransaction)) &&
            !FuzzPQWitness(wrongNetwork, sizeof(wrongNetwork)) &&
            !FuzzPQWitness(badScriptSig, sizeof(badScriptSig));
        if (!expectedResults)
            return 1;

        // Exercise every mutation mask without relying on an installed AFL
        // binary. The two long inputs reach every signature/key byte offset.
        for (unsigned int mode = 0; mode < 256; ++mode) {
            std::vector<uint8_t> sample(PQ_FUZZ_MAGIC,
                PQ_FUZZ_MAGIC + sizeof(PQ_FUZZ_MAGIC) - 1);
            sample.push_back(static_cast<uint8_t>(mode));
            const size_t payloadSize = mode == 1 ? mldsa::SIGNATURE_BYTES :
                mode == 2 ? mldsa::PUBLICKEY_BYTES : 16 + (mode % 17);
            for (size_t i = 0; i < payloadSize; ++i)
                sample.push_back(static_cast<uint8_t>((mode * 73 + i * 29) & 0xff));
            if (test_one_input(sample) != 0)
                return 1;
        }
        std::printf("PQ witness fuzz smoke: 1 valid, 7 invalid, 256 mutations\n");
        return 0;
    }
#ifdef __AFL_INIT
    // Enable AFL deferred forkserver mode. Requires compilation using
    // afl-clang-fast++. See fuzzing.md for details.
    __AFL_INIT();
#endif

#ifdef __AFL_LOOP
    // Enable AFL persistent mode. Requires compilation using afl-clang-fast++.
    // See fuzzing.md for details.
    int ret = 0;
    while (__AFL_LOOP(1000)) {
        std::vector<uint8_t> buffer;
        if (!read_stdin(buffer)) {
            continue;
        }
        ret = test_one_input(buffer);
    }
    return ret;
#else
    std::vector<uint8_t> buffer;
    if (!read_stdin(buffer))
    {
        return 0;
    }
    return test_one_input(buffer);
#endif
}
