// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockencodings.h"
#include "consensus/merkle.h"
#include "chainparams.h"
#include "random.h"

#include "test/test_raven.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

#include <boost/test/unit_test.hpp>

std::vector<std::pair<uint256, CTransactionRef>> extra_txn;

namespace {

void AppendLE32(std::vector<unsigned char>& bytes, uint32_t value)
{
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<unsigned char>(value >> shift));
    }
}

void AppendCompactSize(std::vector<unsigned char>& bytes, uint64_t value)
{
    if (value < 253) {
        bytes.push_back(static_cast<unsigned char>(value));
    } else if (value <= std::numeric_limits<uint16_t>::max()) {
        bytes.push_back(253);
        bytes.push_back(static_cast<unsigned char>(value));
        bytes.push_back(static_cast<unsigned char>(value >> 8));
    } else {
        BOOST_REQUIRE(value <= std::numeric_limits<uint32_t>::max());
        bytes.push_back(254);
        AppendLE32(bytes, static_cast<uint32_t>(value));
    }
}

void AppendEmptyTransaction(std::vector<unsigned char>& bytes)
{
    AppendLE32(bytes, CTransaction::CURRENT_VERSION);
    bytes.push_back(0); // empty vin
    bytes.push_back(0); // empty vout / zero optional-data flag
    AppendLE32(bytes, 0);
}

class PrefixReadStream
{
private:
    std::vector<unsigned char> m_bytes;
    size_t m_position{0};

public:
    bool read_past_end{false};

    explicit PrefixReadStream(std::vector<unsigned char> bytes) :
        m_bytes(std::move(bytes)) {}

    int GetType() const { return SER_NETWORK; }
    int GetVersion() const { return PROTOCOL_VERSION; }
    size_t Position() const { return m_position; }
    size_t Size() const { return m_bytes.size(); }

    void read(char* destination, size_t size)
    {
        if (size > m_bytes.size() - m_position) {
            read_past_end = true;
            throw std::ios_base::failure("test stream read past prefix");
        }
        if (size != 0) {
            std::memcpy(destination, m_bytes.data() + m_position, size);
            m_position += size;
        }
    }

    template <typename T>
    PrefixReadStream& operator>>(T& value)
    {
        ::Unserialize(*this, value);
        return *this;
    }
};

std::vector<unsigned char> LegacyBlockPrefix(uint64_t transactionCount)
{
    std::vector<unsigned char> bytes(80, 0); // nTime=0 selects the 80-byte header
    AppendCompactSize(bytes, transactionCount);
    return bytes;
}

std::vector<unsigned char> BlockTransactionsPrefix(uint64_t transactionCount)
{
    std::vector<unsigned char> bytes(32, 0); // block hash
    AppendCompactSize(bytes, transactionCount);
    return bytes;
}

std::vector<unsigned char> CompactBlockPrefix(uint64_t shortIDCount)
{
    std::vector<unsigned char> bytes(80, 0); // legacy header
    bytes.insert(bytes.end(), 8, 0);         // nonce
    AppendCompactSize(bytes, shortIDCount);
    return bytes;
}

} // namespace

struct RegtestingSetup : public TestingSetup
{
    RegtestingSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {}
};

BOOST_FIXTURE_TEST_SUITE(blockencodings_tests, RegtestingSetup)

    static CBlock BuildBlockTestCase()
    {
        CBlock block;
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].scriptSig.resize(10);
        tx.vout.resize(1);
        tx.vout[0].nValue = 42;

        block.vtx.resize(3);
        block.vtx[0] = MakeTransactionRef(tx);
        block.nVersion = 42;
        block.hashPrevBlock = InsecureRand256();
        block.nBits = 0x207fffff;

        tx.vin[0].prevout.hash = InsecureRand256();
        tx.vin[0].prevout.n = 0;
        block.vtx[1] = MakeTransactionRef(tx);

        tx.vin.resize(10);
        for (size_t i = 0; i < tx.vin.size(); i++)
        {
            tx.vin[i].prevout.hash = InsecureRand256();
            tx.vin[i].prevout.n = 0;
        }
        block.vtx[2] = MakeTransactionRef(tx);

        bool mutated;
        block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
        assert(!mutated);
        while (!CheckProofOfWork(block.GetHash(), block.nBits, GetParams().GetConsensus())) ++block.nNonce;
        return block;
    }

// Number of shared use_counts we expect for a tx we haven't touched
// == 2 (mempool + our copy from the GetSharedTx call)
#define SHARED_TX_OFFSET 2

    BOOST_AUTO_TEST_CASE(simple_round_trip_test)
    {
        BOOST_TEST_MESSAGE("Running Simple Round Trip Test");

        CTxMemPool pool;
        TestMemPoolEntryHelper entry;
        CBlock block(BuildBlockTestCase());

        pool.addUnchecked(block.vtx[2]->GetHash(), entry.FromTx(*block.vtx[2]));
        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

        // Do a simple ShortTxIDs RT
        {
            CBlockHeaderAndShortTxIDs shortIDs(block, true);

            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << shortIDs;

            CBlockHeaderAndShortTxIDs shortIDs2;
            stream >> shortIDs2;
            PartiallyDownloadedBlock partialBlock(&pool);
            BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
            BOOST_CHECK(partialBlock.IsTxAvailable(0));
            BOOST_CHECK(!partialBlock.IsTxAvailable(1));
            BOOST_CHECK(partialBlock.IsTxAvailable(2));

            BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);

            size_t poolSize = pool.size();
            pool.removeRecursive(*block.vtx[2]);
            BOOST_CHECK_EQUAL(pool.size(), poolSize - 1);
            CBlock block2;
            {
                PartiallyDownloadedBlock tmp = partialBlock;
                BOOST_CHECK(partialBlock.FillBlock(block2, {}) == READ_STATUS_INVALID); // No transactions
                partialBlock = tmp;
            }
            // Wrong transaction
            {
                PartiallyDownloadedBlock tmp = partialBlock;
                partialBlock.FillBlock(block2, {block.vtx[2]}); // Current implementation doesn't check txn here, but don't require that
                partialBlock = tmp;
            }
            bool mutated;
            BOOST_CHECK(block.hashMerkleRoot != BlockMerkleRoot(block2, &mutated));
            CBlock block3;
            BOOST_CHECK(partialBlock.FillBlock(block3, {block.vtx[1]}) == READ_STATUS_OK);
            BOOST_CHECK_EQUAL(block.GetHash().ToString(), block3.GetHash().ToString());
            BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block3, &mutated).ToString());
            BOOST_CHECK(!mutated);
        }
    }

    BOOST_AUTO_TEST_CASE(consumed_partial_block_fails_closed_after_fallback)
    {
        CTxMemPool pool;
        const CBlock block = BuildBlockTestCase();
        CBlockHeaderAndShortTxIDs compact(block, true);
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << compact;
        CBlockHeaderAndShortTxIDs decoded;
        stream >> decoded;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_REQUIRE_EQUAL(partialBlock.InitData(decoded, extra_txn),
                            READ_STATUS_OK);
        size_t missing = 0;
        BOOST_REQUIRE(partialBlock.TryGetMissingTxCount(missing));
        BOOST_REQUIRE_EQUAL(missing, 2U);

        // Preserve the expected cardinality but duplicate one transaction so
        // CheckBlock reports a possible compact-relay/merkle collision.
        std::vector<CTransactionRef> wrongTransactions(missing, block.vtx[1]);
        CBlock reconstructed;
        BOOST_REQUIRE_EQUAL(partialBlock.FillBlock(reconstructed,
                                                   wrongTransactions),
                            READ_STATUS_FAILED);

        BOOST_CHECK(!partialBlock.TryGetMissingTxCount(missing));
        BOOST_CHECK_EQUAL(partialBlock.FillBlock(reconstructed,
                                                 wrongTransactions),
                          READ_STATUS_INVALID);
    }

    class TestHeaderAndShortIDs
    {
        // Utility to encode custom CBlockHeaderAndShortTxIDs
    public:
        CBlockHeader header;
        uint64_t nonce;
        std::vector<uint64_t> shorttxids;
        std::vector<PrefilledTransaction> prefilledtxn;

        explicit TestHeaderAndShortIDs(const CBlockHeaderAndShortTxIDs &orig)
        {
            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << orig;
            stream >> *this;
        }

        explicit TestHeaderAndShortIDs(const CBlock &block) :
                TestHeaderAndShortIDs(CBlockHeaderAndShortTxIDs(block, true))
        {}

        uint64_t GetShortID(const uint256 &txhash) const
        {
            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << *this;
            CBlockHeaderAndShortTxIDs base;
            stream >> base;
            return base.GetShortID(txhash);
        }

        ADD_SERIALIZE_METHODS;

        template<typename Stream, typename Operation>
        inline void SerializationOp(Stream &s, Operation ser_action)
        {
            READWRITE(header);
            READWRITE(nonce);
            size_t shorttxids_size = shorttxids.size();
            READWRITE(VARINT(shorttxids_size));
            shorttxids.resize(shorttxids_size);
            for (size_t i = 0; i < shorttxids.size(); i++)
            {
                uint32_t lsb = shorttxids[i] & 0xffffffff;
                uint16_t msb = (shorttxids[i] >> 32) & 0xffff;
                READWRITE(lsb);
                READWRITE(msb);
                shorttxids[i] = (uint64_t(msb) << 32) | uint64_t(lsb);
            }
            READWRITE(prefilledtxn);
        }
    };

    BOOST_AUTO_TEST_CASE(non_coinbase_preforward_rt_test)
    {
        BOOST_TEST_MESSAGE("Running Non Coinbase Forward RT Test");

        CTxMemPool pool;
        TestMemPoolEntryHelper entry;
        CBlock block(BuildBlockTestCase());

        pool.addUnchecked(block.vtx[2]->GetHash(), entry.FromTx(*block.vtx[2]));
        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

        uint256 txhash;

        // Test with pre-forwarding tx 1, but not coinbase
        {
            TestHeaderAndShortIDs shortIDs(block);
            shortIDs.prefilledtxn.resize(1);
            shortIDs.prefilledtxn[0] = {1, block.vtx[1]};
            shortIDs.shorttxids.resize(2);
            shortIDs.shorttxids[0] = shortIDs.GetShortID(block.vtx[0]->GetHash());
            shortIDs.shorttxids[1] = shortIDs.GetShortID(block.vtx[2]->GetHash());

            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << shortIDs;

            CBlockHeaderAndShortTxIDs shortIDs2;
            stream >> shortIDs2;

            PartiallyDownloadedBlock partialBlock(&pool);
            BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
            BOOST_CHECK(!partialBlock.IsTxAvailable(0));
            BOOST_CHECK(partialBlock.IsTxAvailable(1));
            BOOST_CHECK(partialBlock.IsTxAvailable(2));

            BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);

            CBlock block2;
            {
                PartiallyDownloadedBlock tmp = partialBlock;
                BOOST_CHECK(partialBlock.FillBlock(block2, {}) == READ_STATUS_INVALID); // No transactions
                partialBlock = tmp;
            }

            // Wrong transaction
            {
                PartiallyDownloadedBlock tmp = partialBlock;
                partialBlock.FillBlock(block2, {block.vtx[1]}); // Current implementation doesn't check txn here, but don't require that
                partialBlock = tmp;
            }
            bool mutated;
            BOOST_CHECK(block.hashMerkleRoot != BlockMerkleRoot(block2, &mutated));

            CBlock block3;
            PartiallyDownloadedBlock partialBlockCopy = partialBlock;
            BOOST_CHECK(partialBlock.FillBlock(block3, {block.vtx[0]}) == READ_STATUS_OK);
            BOOST_CHECK_EQUAL(block.GetHash().ToString(), block3.GetHash().ToString());
            BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block3, &mutated).ToString());
            BOOST_CHECK(!mutated);

            txhash = block.vtx[2]->GetHash();
            block.vtx.clear();
            block2.vtx.clear();
            block3.vtx.clear();
            BOOST_CHECK_EQUAL(pool.mapTx.find(txhash)->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1); // + 1 because of partialBlockCopy.
        }
        BOOST_CHECK_EQUAL(pool.mapTx.find(txhash)->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);
    }

    BOOST_AUTO_TEST_CASE(sufficient_preforward_rt_test)
    {
        BOOST_TEST_MESSAGE("Running Sufficient Preforward RT Test");

        CTxMemPool pool;
        TestMemPoolEntryHelper entry;
        CBlock block(BuildBlockTestCase());

        pool.addUnchecked(block.vtx[1]->GetHash(), entry.FromTx(*block.vtx[1]));
        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[1]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

        uint256 txhash;

        // Test with pre-forwarding coinbase + tx 2 with tx 1 in mempool
        {
            TestHeaderAndShortIDs shortIDs(block);
            shortIDs.prefilledtxn.resize(2);
            shortIDs.prefilledtxn[0] = {0, block.vtx[0]};
            shortIDs.prefilledtxn[1] = {1, block.vtx[2]}; // id == 1 as it is 1 after index 1
            shortIDs.shorttxids.resize(1);
            shortIDs.shorttxids[0] = shortIDs.GetShortID(block.vtx[1]->GetHash());

            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << shortIDs;

            CBlockHeaderAndShortTxIDs shortIDs2;
            stream >> shortIDs2;

            PartiallyDownloadedBlock partialBlock(&pool);
            BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
            BOOST_CHECK(partialBlock.IsTxAvailable(0));
            BOOST_CHECK(partialBlock.IsTxAvailable(1));
            BOOST_CHECK(partialBlock.IsTxAvailable(2));

            BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[1]->GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);

            CBlock block2;
            PartiallyDownloadedBlock partialBlockCopy = partialBlock;
            BOOST_CHECK(partialBlock.FillBlock(block2, {}) == READ_STATUS_OK);
            BOOST_CHECK_EQUAL(block.GetHash().ToString(), block2.GetHash().ToString());
            bool mutated;
            BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block2, &mutated).ToString());
            BOOST_CHECK(!mutated);

            txhash = block.vtx[1]->GetHash();
            block.vtx.clear();
            block2.vtx.clear();
            BOOST_CHECK_EQUAL(pool.mapTx.find(txhash)->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1); // + 1 because of partialBlockCopy.
        }
        BOOST_CHECK_EQUAL(pool.mapTx.find(txhash)->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);
    }

    BOOST_AUTO_TEST_CASE(empty_block_round_trip_test)
    {
        BOOST_TEST_MESSAGE("Running Empty BLock Round Trip Test");

        CTxMemPool pool;
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].scriptSig.resize(10);
        coinbase.vout.resize(1);
        coinbase.vout[0].nValue = 42;

        CBlock block;
        block.vtx.resize(1);
        block.vtx[0] = MakeTransactionRef(std::move(coinbase));
        block.nVersion = 42;
        block.hashPrevBlock = InsecureRand256();
        block.nBits = 0x207fffff;

        bool mutated;
        block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
        assert(!mutated);
        while (!CheckProofOfWork(block.GetHash(), block.nBits, GetParams().GetConsensus())) ++block.nNonce;

        // Test simple header round-trip with only coinbase
        {
            CBlockHeaderAndShortTxIDs shortIDs(block, false);

            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << shortIDs;

            CBlockHeaderAndShortTxIDs shortIDs2;
            stream >> shortIDs2;

            PartiallyDownloadedBlock partialBlock(&pool);
            BOOST_CHECK(partialBlock.InitData(shortIDs2, extra_txn) == READ_STATUS_OK);
            BOOST_CHECK(partialBlock.IsTxAvailable(0));

            CBlock block2;
            std::vector<CTransactionRef> vtx_missing;
            BOOST_CHECK(partialBlock.FillBlock(block2, vtx_missing) == READ_STATUS_OK);
            BOOST_CHECK_EQUAL(block.GetHash().ToString(), block2.GetHash().ToString());
            BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block2, &mutated).ToString());
            BOOST_CHECK(!mutated);
        }
    }

    BOOST_AUTO_TEST_CASE(transactions_request_serialization_test)
    {
        BOOST_TEST_MESSAGE("Running Transaction Request Serialization Test");

        BlockTransactionsRequest req1;
        req1.blockhash = InsecureRand256();
        req1.indexes.resize(4);
        req1.indexes[0] = 0;
        req1.indexes[1] = 1;
        req1.indexes[2] = 3;
        req1.indexes[3] = 4;

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << req1;

        BlockTransactionsRequest req2;
        stream >> req2;

        BOOST_CHECK_EQUAL(req1.blockhash.ToString(), req2.blockhash.ToString());
        BOOST_CHECK_EQUAL(req1.indexes.size(), req2.indexes.size());
        BOOST_CHECK_EQUAL(req1.indexes[0], req2.indexes[0]);
        BOOST_CHECK_EQUAL(req1.indexes[1], req2.indexes[1]);
        BOOST_CHECK_EQUAL(req1.indexes[2], req2.indexes[2]);
        BOOST_CHECK_EQUAL(req1.indexes[3], req2.indexes[3]);
    }

    BOOST_AUTO_TEST_CASE(block_family_counts_reject_before_element_read)
    {
        const uint64_t invalidCount = MAX_BLOCK_TRANSACTION_COUNT + 1;
        BOOST_REQUIRE_EQUAL(MAX_BLOCK_TRANSACTION_COUNT, 66666U);

        PrefixReadStream blockStream(LegacyBlockPrefix(invalidCount));
        CBlock block;
        block.vtx.push_back(MakeTransactionRef(CMutableTransaction()));
        BOOST_CHECK_THROW(blockStream >> block, std::ios_base::failure);
        BOOST_CHECK(!blockStream.read_past_end);
        BOOST_CHECK_EQUAL(blockStream.Position(), blockStream.Size());
        BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);

        PrefixReadStream blockTransactionsStream(
            BlockTransactionsPrefix(invalidCount));
        BlockTransactions blockTransactions;
        blockTransactions.txn.push_back(
            MakeTransactionRef(CMutableTransaction()));
        BOOST_CHECK_THROW(blockTransactionsStream >> blockTransactions,
                          std::ios_base::failure);
        BOOST_CHECK(!blockTransactionsStream.read_past_end);
        BOOST_CHECK_EQUAL(blockTransactionsStream.Position(),
                          blockTransactionsStream.Size());
        BOOST_REQUIRE_EQUAL(blockTransactions.txn.size(), 1U);

        PrefixReadStream shortIDStream(CompactBlockPrefix(invalidCount));
        CBlockHeaderAndShortTxIDs shortIDs;
        BOOST_CHECK_THROW(shortIDStream >> shortIDs, std::ios_base::failure);
        BOOST_CHECK(!shortIDStream.read_past_end);
        BOOST_CHECK_EQUAL(shortIDStream.Position(), shortIDStream.Size());

        std::vector<unsigned char> prefilledPrefix = CompactBlockPrefix(0);
        AppendCompactSize(prefilledPrefix, invalidCount);
        PrefixReadStream prefilledStream(std::move(prefilledPrefix));
        CBlockHeaderAndShortTxIDs prefilled;
        BOOST_CHECK_THROW(prefilledStream >> prefilled, std::ios_base::failure);
        BOOST_CHECK(!prefilledStream.read_past_end);
        BOOST_CHECK_EQUAL(prefilledStream.Position(), prefilledStream.Size());

        std::vector<unsigned char> combinedPrefix =
            CompactBlockPrefix(MAX_BLOCK_TRANSACTION_COUNT);
        combinedPrefix.insert(combinedPrefix.end(),
                              MAX_BLOCK_TRANSACTION_COUNT * 6, 0);
        AppendCompactSize(combinedPrefix, 1);
        PrefixReadStream combinedStream(std::move(combinedPrefix));
        CBlockHeaderAndShortTxIDs combined;
        BOOST_CHECK_THROW(combinedStream >> combined, std::ios_base::failure);
        BOOST_CHECK(!combinedStream.read_past_end);
        BOOST_CHECK_EQUAL(combinedStream.Position(), combinedStream.Size());
    }

    BOOST_AUTO_TEST_CASE(block_family_transaction_count_boundary_roundtrips)
    {
        std::vector<unsigned char> blockWire =
            LegacyBlockPrefix(MAX_BLOCK_TRANSACTION_COUNT);
        blockWire.reserve(blockWire.size() + MAX_BLOCK_TRANSACTION_COUNT * 10);
        for (size_t i = 0; i < MAX_BLOCK_TRANSACTION_COUNT; ++i) {
            AppendEmptyTransaction(blockWire);
        }

        CDataStream blockInput(blockWire, SER_NETWORK, PROTOCOL_VERSION);
        CBlock block;
        blockInput >> block;
        BOOST_REQUIRE(blockInput.empty());
        BOOST_REQUIRE_EQUAL(block.vtx.size(), MAX_BLOCK_TRANSACTION_COUNT);
        CDataStream blockOutput(SER_NETWORK, PROTOCOL_VERSION);
        blockOutput << block;
        BOOST_REQUIRE_EQUAL(blockOutput.size(), blockWire.size());
        BOOST_CHECK_EQUAL(std::memcmp(blockOutput.data(), blockWire.data(),
                                      blockWire.size()), 0);

        std::vector<unsigned char> responseWire =
            BlockTransactionsPrefix(MAX_BLOCK_TRANSACTION_COUNT);
        responseWire.reserve(responseWire.size() +
                             MAX_BLOCK_TRANSACTION_COUNT * 10);
        for (size_t i = 0; i < MAX_BLOCK_TRANSACTION_COUNT; ++i) {
            AppendEmptyTransaction(responseWire);
        }

        CDataStream responseInput(responseWire, SER_NETWORK, PROTOCOL_VERSION);
        BlockTransactions response;
        responseInput >> response;
        BOOST_REQUIRE(responseInput.empty());
        BOOST_REQUIRE_EQUAL(response.txn.size(), MAX_BLOCK_TRANSACTION_COUNT);
        CDataStream responseOutput(SER_NETWORK, PROTOCOL_VERSION);
        responseOutput << response;
        BOOST_REQUIRE_EQUAL(responseOutput.size(), responseWire.size());
        BOOST_CHECK_EQUAL(std::memcmp(responseOutput.data(), responseWire.data(),
                                      responseWire.size()), 0);

        std::vector<unsigned char> compactWire =
            CompactBlockPrefix(MAX_BLOCK_TRANSACTION_COUNT);
        compactWire.insert(compactWire.end(), MAX_BLOCK_TRANSACTION_COUNT * 6, 0);
        AppendCompactSize(compactWire, 0); // no prefilled transactions

        CDataStream compactInput(compactWire, SER_NETWORK, PROTOCOL_VERSION);
        CBlockHeaderAndShortTxIDs compactBlock;
        compactInput >> compactBlock;
        BOOST_REQUIRE(compactInput.empty());
        BOOST_REQUIRE_EQUAL(compactBlock.BlockTxCount(),
                            MAX_BLOCK_TRANSACTION_COUNT);
        CDataStream compactOutput(SER_NETWORK, PROTOCOL_VERSION);
        compactOutput << compactBlock;
        BOOST_REQUIRE_EQUAL(compactOutput.size(), compactWire.size());
        BOOST_CHECK_EQUAL(std::memcmp(compactOutput.data(), compactWire.data(),
                                      compactWire.size()), 0);
    }

    BOOST_AUTO_TEST_CASE(block_family_count_bounds_are_atomic_and_apply_on_write)
    {
        const CTransactionRef emptyTransaction =
            MakeTransactionRef(CMutableTransaction());

        CBlock oversizedBlock;
        oversizedBlock.vtx.resize(MAX_BLOCK_TRANSACTION_COUNT + 1,
                                  emptyTransaction);
        CDataStream blockOutput(SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK_THROW(blockOutput << oversizedBlock,
                          std::ios_base::failure);
        BOOST_CHECK_THROW(CBlockHeaderAndShortTxIDs(oversizedBlock, true),
                          std::invalid_argument);

        BlockTransactions oversizedResponse;
        oversizedResponse.txn.resize(MAX_BLOCK_TRANSACTION_COUNT + 1,
                                     emptyTransaction);
        CDataStream responseOutput(SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK_THROW(responseOutput << oversizedResponse,
                          std::ios_base::failure);

        std::vector<unsigned char> truncatedBlock = LegacyBlockPrefix(1);
        AppendLE32(truncatedBlock, CTransaction::CURRENT_VERSION);
        CDataStream blockInput(truncatedBlock, SER_NETWORK, PROTOCOL_VERSION);
        CBlock block;
        block.vtx.push_back(emptyTransaction);
        BOOST_CHECK_THROW(blockInput >> block, std::ios_base::failure);
        BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);
        BOOST_CHECK(block.vtx[0] == emptyTransaction);

        std::vector<unsigned char> truncatedResponse =
            BlockTransactionsPrefix(1);
        AppendLE32(truncatedResponse, CTransaction::CURRENT_VERSION);
        CDataStream responseInput(truncatedResponse, SER_NETWORK,
                                  PROTOCOL_VERSION);
        BlockTransactions response;
        response.txn.push_back(emptyTransaction);
        BOOST_CHECK_THROW(responseInput >> response, std::ios_base::failure);
        BOOST_REQUIRE_EQUAL(response.txn.size(), 1U);
        BOOST_CHECK(response.txn[0] == emptyTransaction);

        std::vector<unsigned char> validCompact = CompactBlockPrefix(1);
        validCompact.insert(validCompact.end(), 6, 0);
        AppendCompactSize(validCompact, 0);
        CDataStream validCompactInput(validCompact, SER_NETWORK,
                                      PROTOCOL_VERSION);
        CBlockHeaderAndShortTxIDs compactBlock;
        validCompactInput >> compactBlock;
        BOOST_REQUIRE_EQUAL(compactBlock.BlockTxCount(), 1U);

        std::vector<unsigned char> truncatedCompact = CompactBlockPrefix(0);
        AppendCompactSize(truncatedCompact, 1);
        AppendCompactSize(truncatedCompact, 0);
        AppendLE32(truncatedCompact, CTransaction::CURRENT_VERSION);
        CDataStream compactInput(truncatedCompact, SER_NETWORK,
                                 PROTOCOL_VERSION);
        BOOST_CHECK_THROW(compactInput >> compactBlock,
                          std::ios_base::failure);
        BOOST_CHECK_EQUAL(compactBlock.BlockTxCount(), 1U);
    }

BOOST_AUTO_TEST_SUITE_END()
