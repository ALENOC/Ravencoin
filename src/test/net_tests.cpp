// Copyright (c) 2012-2016 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "addrman.h"
#include "test/test_raven.h"
#include <string>
#include <boost/test/unit_test.hpp>
#include "hash.h"
#include "serialize.h"
#include "streams.h"
#include "net.h"
#include "netbase.h"
#include "chainparams.h"
#include "util.h"

#include <atomic>
#include <thread>

static std::unique_ptr<CNode> MakeTestNode(NodeId id, CNetMessageBuffer& recvBuffer)
{
    return std::unique_ptr<CNode>(new CNode(id, NODE_NETWORK, 0, INVALID_SOCKET,
                                            CAddress(), 0, 0, CAddress(), recvBuffer));
}

static void ReceiveHeader(CNode& node, unsigned int nMessageSize)
{
    CDataStream header(SER_NETWORK, INIT_PROTO_VERSION);
    header << CMessageHeader(GetParams().MessageStart(), NetMsgType::BLOCK, nMessageSize);
    bool complete = false;
    BOOST_REQUIRE(node.ReceiveMsgBytes(header.data(), static_cast<unsigned int>(header.size()), complete));
    BOOST_CHECK(!complete);
}

static bool ReceivePayload(CNode& node, size_t nBytes, size_t nChunkSize, bool& complete)
{
    std::vector<char> chunk(nChunkSize, 0);
    complete = false;
    while (nBytes != 0) {
        const size_t nNow = std::min(nBytes, chunk.size());
        if (!node.ReceiveMsgBytes(chunk.data(), static_cast<unsigned int>(nNow), complete)) {
            return false;
        }
        nBytes -= nNow;
    }
    return true;
}

class CAddrManSerializationMock : public CAddrMan
{
public:
    virtual void Serialize(CDataStream &s) const = 0;

    //! Ensure that bucket placement is always the same for testing purposes.
    void MakeDeterministic()
    {
        nKey.SetNull();
        insecure_rand = FastRandomContext(true);
    }
};

class CAddrManUncorrupted : public CAddrManSerializationMock
{
public:
    void Serialize(CDataStream &s) const override
    {
        CAddrMan::Serialize(s);
    }
};

class CAddrManCorrupted : public CAddrManSerializationMock
{
public:
    void Serialize(CDataStream &s) const override
    {
        // Produces corrupt output that claims addrman has 20 addrs when it only has one addr.
        unsigned char nVersion = 1;
        s << nVersion;
        s << ((unsigned char) 32);
        s << nKey;
        s << 10; // nNew
        s << 10; // nTried

        int nUBuckets = ADDRMAN_NEW_BUCKET_COUNT ^(1 << 30);
        s << nUBuckets;

        CService serv;
        Lookup("252.1.1.1", serv, 7777, false);
        CAddress addr = CAddress(serv, NODE_NONE);
        CNetAddr resolved;
        LookupHost("252.2.2.2", resolved, false);
        CAddrInfo info = CAddrInfo(addr, resolved);
        s << info;
    }
};

CDataStream AddrmanToStream(CAddrManSerializationMock &_addrman)
{
    CDataStream ssPeersIn(SER_DISK, CLIENT_VERSION);
    ssPeersIn << FLATDATA(GetParams().MessageStart());
    ssPeersIn << _addrman;
    std::string str = ssPeersIn.str();
    std::vector<unsigned char> vchData(str.begin(), str.end());
    return CDataStream(vchData, SER_DISK, CLIENT_VERSION);
}

BOOST_FIXTURE_TEST_SUITE(net_tests, BasicTestingSetup)

    BOOST_AUTO_TEST_CASE(cnode_listen_port_test)
    {
        BOOST_TEST_MESSAGE("Running cNode Listen Port Test");

        // test default
        unsigned short port = GetListenPort();
        BOOST_CHECK(port == GetParams().GetDefaultPort());
        // test set port
        unsigned short altPort = 12345;
        gArgs.SoftSetArg("-port", std::to_string(altPort));
        port = GetListenPort();
        BOOST_CHECK(port == altPort);
    }

    BOOST_AUTO_TEST_CASE(caddrdb_read_test)
    {
        BOOST_TEST_MESSAGE("Running cAddrDB Read Test");

        CAddrManUncorrupted addrmanUncorrupted;
        addrmanUncorrupted.MakeDeterministic();

        CService addr1, addr2, addr3;
        Lookup("250.7.1.1", addr1, 8767, false);
        Lookup("250.7.2.2", addr2, 9999, false);
        Lookup("250.7.3.3", addr3, 9999, false);

        // Add three addresses to new table.
        CService source;
        Lookup("252.5.1.1", source, 8767, false);
        addrmanUncorrupted.Add(CAddress(addr1, NODE_NONE), source);
        addrmanUncorrupted.Add(CAddress(addr2, NODE_NONE), source);
        addrmanUncorrupted.Add(CAddress(addr3, NODE_NONE), source);

        // Test that the de-serialization does not throw an exception.
        CDataStream ssPeers1 = AddrmanToStream(addrmanUncorrupted);
        bool exceptionThrown = false;
        CAddrMan addrman1;

        BOOST_CHECK(addrman1.size() == 0);
        try
        {
            unsigned char pchMsgTmp[4];
            ssPeers1 >> FLATDATA(pchMsgTmp);
            ssPeers1 >> addrman1;
        } catch (const std::exception &e)
        {
            exceptionThrown = true;
        }

        BOOST_CHECK(addrman1.size() == 3);
        BOOST_CHECK(exceptionThrown == false);

        // Test that CAddrDB::Read creates an addrman with the correct number of addrs.
        CDataStream ssPeers2 = AddrmanToStream(addrmanUncorrupted);

        CAddrMan addrman2;
        CAddrDB adb;
        BOOST_CHECK(addrman2.size() == 0);
        adb.Read(addrman2, ssPeers2);
        BOOST_CHECK(addrman2.size() == 3);
    }


    BOOST_AUTO_TEST_CASE(caddrdb_read_corrupted_test)
    {
        BOOST_TEST_MESSAGE("Running cAddrDB Read Corrupted Test");

        CAddrManCorrupted addrmanCorrupted;
        addrmanCorrupted.MakeDeterministic();

        // Test that the de-serialization of corrupted addrman throws an exception.
        CDataStream ssPeers1 = AddrmanToStream(addrmanCorrupted);
        bool exceptionThrown = false;
        CAddrMan addrman1;
        BOOST_CHECK(addrman1.size() == 0);
        try
        {
            unsigned char pchMsgTmp[4];
            ssPeers1 >> FLATDATA(pchMsgTmp);
            ssPeers1 >> addrman1;
        } catch (const std::exception &e)
        {
            exceptionThrown = true;
        }
        // Even through de-serialization failed addrman is not left in a clean state.
        BOOST_CHECK(addrman1.size() == 1);
        BOOST_CHECK(exceptionThrown);

        // Test that CAddrDB::Read leaves addrman in a clean state if de-serialization fails.
        CDataStream ssPeers2 = AddrmanToStream(addrmanCorrupted);

        CAddrMan addrman2;
        CAddrDB adb;
        BOOST_CHECK(addrman2.size() == 0);
        adb.Read(addrman2, ssPeers2);
        BOOST_CHECK(addrman2.size() == 0);
    }

    BOOST_AUTO_TEST_CASE(cnode_simple_test)
    {
        BOOST_TEST_MESSAGE("Running cNode Simple Test");

        SOCKET hSocket = INVALID_SOCKET;
        NodeId id = 0;
        int height = 0;

        in_addr ipv4Addr;
        ipv4Addr.s_addr = 0xa0b0c001;

        CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
        std::string pszDest = "";
        bool fInboundIn = false;

        // Test that fFeeler is false by default.
        CNetMessageBuffer recvBuffer(MAX_PROTOCOL_MESSAGE_LENGTH);
        std::unique_ptr<CNode> pnode1(new CNode(id++, NODE_NETWORK, height, hSocket, addr, 0, 0, CAddress(), recvBuffer, pszDest, fInboundIn));
        BOOST_CHECK(pnode1->fInbound == false);
        BOOST_CHECK(pnode1->fFeeler == false);

        fInboundIn = true;
        std::unique_ptr<CNode> pnode2(new CNode(id++, NODE_NETWORK, height, hSocket, addr, 1, 1, CAddress(), recvBuffer, pszDest, fInboundIn));
        BOOST_CHECK(pnode2->fInbound == true);
        BOOST_CHECK(pnode2->fFeeler == false);
    }

    BOOST_AUTO_TEST_CASE(incomplete_message_buffer_concurrent_global_limit)
    {
        static const size_t NODE_COUNT = 4;
        static const size_t CHUNK_SIZE = 64 * 1024;
        static const size_t FIRST_ALLOCATION = CHUNK_SIZE + 256 * 1024;
        static const size_t BUFFER_LIMIT = 2 * FIRST_ALLOCATION;
        CNetMessageBuffer recvBuffer(BUFFER_LIMIT);
        std::vector<std::unique_ptr<CNode>> nodes;
        for (size_t i = 0; i < NODE_COUNT; ++i) {
            nodes.push_back(MakeTestNode(i, recvBuffer));
            ReceiveHeader(*nodes.back(), MAX_PROTOCOL_MESSAGE_LENGTH);
        }

        std::atomic<size_t> ready(0);
        std::atomic<bool> start(false);
        std::vector<int> results(NODE_COUNT, 0);
        std::vector<std::thread> threads;
        for (size_t i = 0; i < NODE_COUNT; ++i) {
            threads.emplace_back([&, i]() {
                ready.fetch_add(1, std::memory_order_release);
                while (!start.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                bool complete = false;
                results[i] = ReceivePayload(*nodes[i], CHUNK_SIZE, CHUNK_SIZE, complete) ? 1 : 0;
            });
        }
        while (ready.load(std::memory_order_acquire) != NODE_COUNT) {
            std::this_thread::yield();
        }
        start.store(true, std::memory_order_release);
        for (auto& thread : threads) {
            thread.join();
        }

        BOOST_CHECK_EQUAL(std::count(results.begin(), results.end(), 1), 2);
        BOOST_CHECK_EQUAL(recvBuffer.Size(), BUFFER_LIMIT);
        nodes.clear();
        BOOST_CHECK_EQUAL(recvBuffer.Size(), 0);
    }

    BOOST_AUTO_TEST_CASE(incomplete_message_buffer_releases_reservations)
    {
        static const size_t MESSAGE_SIZE = 300 * 1024;
        CNetMessageBuffer recvBuffer(MESSAGE_SIZE);
        bool complete = false;

        auto completed = MakeTestNode(0, recvBuffer);
        ReceiveHeader(*completed, MESSAGE_SIZE);
        BOOST_REQUIRE(ReceivePayload(*completed, MESSAGE_SIZE, 64 * 1024, complete));
        BOOST_CHECK(complete);
        BOOST_CHECK_EQUAL(recvBuffer.Size(), 0);

        auto incomplete = MakeTestNode(1, recvBuffer);
        ReceiveHeader(*incomplete, MESSAGE_SIZE);
        BOOST_REQUIRE(ReceivePayload(*incomplete, 1, 1, complete));
        BOOST_CHECK(!complete);
        BOOST_CHECK_GT(recvBuffer.Size(), 0);
        incomplete.reset();
        BOOST_CHECK_EQUAL(recvBuffer.Size(), 0);
    }

    BOOST_AUTO_TEST_CASE(maximum_message_completes_with_global_buffer_limit)
    {
        CNetMessageBuffer recvBuffer(MAX_PROTOCOL_MESSAGE_LENGTH);
        auto node = MakeTestNode(0, recvBuffer);
        ReceiveHeader(*node, MAX_PROTOCOL_MESSAGE_LENGTH);

        bool complete = false;
        BOOST_REQUIRE(ReceivePayload(*node, MAX_PROTOCOL_MESSAGE_LENGTH, 64 * 1024, complete));
        BOOST_CHECK(complete);
        BOOST_CHECK_EQUAL(recvBuffer.Size(), 0);
    }

BOOST_AUTO_TEST_SUITE_END()
