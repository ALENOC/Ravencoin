// Copyright (c) 2018-2020 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "validation.h"
#include "assets.h"
#include "myassetsdb.h"
#include "messages.h"
#include <boost/thread.hpp>

#include <boost/thread.hpp>

static const char MESSAGE_FLAG = 'Z'; // Message
static const char MY_MESSAGE_CHANNEL = 'C'; // My followed Channels
static const char MY_SEEN_ADDRESSES = 'S'; // Addresses that have been seen on the chain
static const char DB_FLAG = 'D'; // Database Flags

static const char MY_TAGGED_ADDRESSES = 'T'; // Addresses that have been tagged
static const char MY_RESTRICTED_ADDRESSES = 'R'; // Addresses that have been restricted
static const char MY_RESTRICTED_UNDO = 'U';

using RestrictedEventKey = std::pair<char, std::pair<std::string, std::string>>;
using RestrictedEventValue = std::pair<int, uint32_t>;
using RestrictedBlockUndo = std::vector<std::pair<RestrictedEventKey,
                                                   std::pair<bool, RestrictedEventValue>>>;

CMessageDB::CMessageDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "messages" / "messages", nCacheSize, fMemory, fWipe) {
}

bool CMessageDB::WriteMessage(const CMessage &message)
{
    return Write(std::make_pair(MESSAGE_FLAG, message.out), message);
}

bool CMessageDB::ReadMessage(const COutPoint &out, CMessage &message)
{
    return Read(std::make_pair(MESSAGE_FLAG, out), message);
}

bool CMessageDB::EraseMessage(const COutPoint &out)
{
    return Erase(std::make_pair(MESSAGE_FLAG, out));
}

bool CMessageDB::LoadMessages(std::set<CMessage>& setMessages)
{
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(MESSAGE_FLAG, COutPoint()));

    // Load messages
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, COutPoint> key;
        if (pcursor->GetKey(key) && key.first == MESSAGE_FLAG) {
            CMessage message;
            if (pcursor->GetValue(message)) {
                setMessages.insert(message);
                pcursor->Next();
            } else {
                LogPrintf("%s: failed to read message\n", __func__);
                pcursor->Next();
            }
        } else {
            break;
        }
    }
    return true;
}

bool CMessageDB::EraseAllMessages(int& count)
{
    std::set<CMessage> setMessages;
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(MESSAGE_FLAG, COutPoint()));

    // Load messages
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, COutPoint> key;
        if (pcursor->GetKey(key) && key.first == MESSAGE_FLAG) {
            CMessage message;
            if (pcursor->GetValue(message)) {
                setMessages.insert(message);
                pcursor->Next();
            } else {
                LogPrintf("%s: failed to read message\n", __func__);
                pcursor->Next();
            }
        } else {
            break;
        }
    }

    count += setMessages.size();
    for (auto message : setMessages)
        EraseMessage(message.out);

    return true;
}

bool CMessageDB::Flush() {
    try {

        for (auto messageRemove : setDirtyMessagesRemove) {
            if (!EraseMessage(messageRemove))
                return error("%s: failed to erase message %s", __func__, messageRemove.ToString());
        }

        for (auto messageAdd : mapDirtyMessagesAdd) {
            if (!WriteMessage(messageAdd.second))
                return error("%s: failed to write message %s", __func__, messageAdd.second.ToString());

            mapDirtyMessagesOrphaned.erase(messageAdd.first);
        }

        for (auto orphans : mapDirtyMessagesOrphaned) {
            CMessage msg = orphans.second;
            msg.status = MessageStatus::ORPHAN;
            if (!WriteMessage(msg))
                return error("%s: failed to write message orphan %s", __func__, msg.ToString());
        }

        setDirtyMessagesRemove.clear();
        mapDirtyMessagesAdd.clear();
        mapDirtyMessagesOrphaned.clear();
    } catch (const std::runtime_error& e) {
        return error("%s : %s ", __func__, std::string("System error while flushing messages: ") + e.what());
    }

    return true;
}

CMessageChannelDB::CMessageChannelDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "messages" / "channels", nCacheSize, fMemory, fWipe) {
}

bool CMessageChannelDB::WriteMyMessageChannel(const std::string& channelname)
{
    return Write(std::make_pair(MY_MESSAGE_CHANNEL, channelname), 1);
}

bool CMessageChannelDB::ReadMyMessageChannel(const std::string& channelname)
{
    int i = 1;
    return Read(std::make_pair(MY_MESSAGE_CHANNEL, channelname), i);
}

bool CMessageChannelDB::EraseMyMessageChannel(const std::string& channelname)
{
    return Erase(std::make_pair(MY_MESSAGE_CHANNEL, channelname));
}

bool CMessageChannelDB::LoadMyMessageChannels(std::set<std::string>& setChannels)
{
    setChannels.clear();
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(MY_MESSAGE_CHANNEL, std::string()));

    // Load messages
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, std::string> key;
        if (pcursor->GetKey(key) && key.first == MY_MESSAGE_CHANNEL) {
            setChannels.insert(key.second);
            pcursor->Next();
        } else {
            break;
        }
    }

    return true;
}

bool CMessageDB::WriteFlag(const std::string &name, bool fValue)
{
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CMessageDB::ReadFlag(const std::string &name, bool &fValue)
{
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}


bool CMessageChannelDB::WriteUsedAddress(const std::string& address)
{
    return Write(std::make_pair(MY_SEEN_ADDRESSES, address), 1);
}
bool CMessageChannelDB::ReadUsedAddress(const std::string& address)
{
    int i;
    return Read(std::make_pair(MY_SEEN_ADDRESSES, address), i);
}
bool CMessageChannelDB::EraseUsedAddress(const std::string& address)
{
    return Erase(std::make_pair(MY_SEEN_ADDRESSES, address));
}

bool CMessageChannelDB::WriteFlag(const std::string &name, bool fValue)
{
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CMessageChannelDB::ReadFlag(const std::string &name, bool &fValue)
{
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CMessageChannelDB::Flush() {
    try {
        LogPrintf("%s: Flushing messagechannelsdb addSize:%u, removeSize:%u, seenAddressSize:%u\n", __func__, setDirtyChannelsAdd.size(), setDirtyChannelsRemove.size(), setDirtySeenAddressAdd.size());

        for (auto channelRemove : setDirtyChannelsRemove) {
            if (!EraseMyMessageChannel(channelRemove))
                return error("%s: failed to erase messagechannel %s", __func__, channelRemove);
        }

        for (auto channelAdd : setDirtyChannelsAdd) {
            if (!WriteMyMessageChannel(channelAdd))
                return error("%s: failed to write messagechannel %s", __func__, channelAdd);
        }

        for (auto seenAddress : setDirtySeenAddressAdd) {
            if (!WriteUsedAddress(seenAddress))
                return error("%s: failed to write seenaddress %s", __func__, seenAddress);
        }

        setDirtyChannelsRemove.clear();
        setDirtyChannelsAdd.clear();
        setDirtySeenAddressAdd.clear();
        setSubscribedChannelsAskedForFalse.clear();
        setAddressAskedForFalse.clear();
    } catch (const std::runtime_error& e) {
        return error("%s : %s ", __func__, std::string("System error while flushing messagechannels: ") + e.what());
    }

    return true;
}


CMyRestrictedDB::CMyRestrictedDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "myrestricted", nCacheSize, fMemory, fWipe) {
}

bool CMyRestrictedDB::WriteTaggedAddress(const std::string& address, const std::string& tag_name, const bool fAdd, const uint32_t& nHeight)
{
    return Write(std::make_pair(MY_TAGGED_ADDRESSES, std::make_pair(address, tag_name)), std::make_pair(fAdd ? 1 : 0, nHeight));
}
bool CMyRestrictedDB::ReadTaggedAddress(const std::string& address, const std::string& tag_name, bool& fAdd, uint32_t& nHeight)
{
    std::pair<int, uint32_t> value;
    bool ret = Read(std::make_pair(MY_TAGGED_ADDRESSES, std::make_pair(address, tag_name)), value);
    fAdd = value.first;
    nHeight = value.second;
    return ret;
}
bool CMyRestrictedDB::EraseTaggedAddress(const std::string& address, const std::string& tag_name)
{
    return Erase(std::make_pair(MY_TAGGED_ADDRESSES, std::make_pair(address, tag_name)));
}
bool CMyRestrictedDB::LoadMyTaggedAddresses(std::vector<std::tuple<std::string, std::string, bool, uint32_t> >& vecTaggedAddresses)
{
    vecTaggedAddresses.clear();
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(MY_TAGGED_ADDRESSES, std::make_pair(std::string(), std::string())));

    // Load messages
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, std::pair<std::string, std::string>> key;
        if (pcursor->GetKey(key) && key.first == MY_TAGGED_ADDRESSES) {
            std::pair<int, uint32_t> value;
            if (pcursor->GetValue(value)) {
                vecTaggedAddresses.emplace_back(std::make_tuple(key.second.first, key.second.second, value.first ? true : false, value.second));
            }
            pcursor->Next();
        } else {
            break;
        }
    }

    return true;
}

bool CMyRestrictedDB::WriteRestrictedAddress(const std::string& address, const std::string& tag_name, const bool fAdd, const uint32_t& nHeight)
{
    return Write(std::make_pair(MY_RESTRICTED_ADDRESSES, std::make_pair(address, tag_name)), std::make_pair(fAdd ? 1 : 0, nHeight));
}

bool CMyRestrictedDB::ReadRestrictedAddress(const std::string& address, const std::string& tag_name, bool& fAdd, uint32_t& nHeight)
{
    std::pair<int, uint32_t> value;
    bool ret = Read(std::make_pair(MY_RESTRICTED_ADDRESSES, std::make_pair(address, tag_name)), value);
    fAdd = value.first;
    nHeight = value.second;
    return ret;
}

bool CMyRestrictedDB::EraseRestrictedAddress(const std::string& address, const std::string& tag_name)
{
    return Erase(std::make_pair(MY_RESTRICTED_ADDRESSES, std::make_pair(address, tag_name)));
}

bool CMyRestrictedDB::LoadMyRestrictedAddresses(std::vector<std::tuple<std::string, std::string, bool, uint32_t> >& vecRestrictedAddresses)
{
    vecRestrictedAddresses.clear();
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(MY_RESTRICTED_ADDRESSES, std::make_pair(std::string(), std::string())));

    // Load messages
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, std::pair<std::string, std::string>> key;
        if (pcursor->GetKey(key) && key.first == MY_RESTRICTED_ADDRESSES) {
            std::pair<int, uint32_t> value;
            if (pcursor->GetValue(value)) {
                vecRestrictedAddresses.emplace_back(std::make_tuple(key.second.first, key.second.second, value.first ? true : false, value.second));
            }
            pcursor->Next();
        } else {
            break;
        }
    }

    return true;
}

bool CMyRestrictedDB::EraseAllRestrictedEvents()
{
    for (char prefix : {MY_TAGGED_ADDRESSES, MY_RESTRICTED_ADDRESSES}) {
        std::unique_ptr<CDBIterator> cursor(NewIterator());
        cursor->Seek(std::make_pair(prefix, std::make_pair(std::string(), std::string())));
        while (cursor->Valid()) {
            CDBBatch batch(*this);
            size_t count = 0;
            while (cursor->Valid() && count < 1024) {
                std::pair<char, std::pair<std::string, std::string>> key;
                if (!cursor->GetKey(key) || key.first != prefix)
                    break;
                batch.Erase(key);
                cursor->Next();
                ++count;
            }
            if (!count)
                break;
            if (!WriteBatch(batch))
                return false;
            boost::this_thread::interruption_point();
        }
    }
    std::unique_ptr<CDBIterator> cursor(NewIterator());
    cursor->Seek(std::make_pair(MY_RESTRICTED_UNDO, uint256()));
    while (cursor->Valid()) {
        CDBBatch batch(*this);
        size_t count = 0;
        while (cursor->Valid() && count < 1024) {
            std::pair<char, uint256> key;
            if (!cursor->GetKey(key) || key.first != MY_RESTRICTED_UNDO)
                break;
            batch.Erase(key);
            cursor->Next();
            ++count;
        }
        if (!count)
            break;
        if (!WriteBatch(batch))
            return false;
        boost::this_thread::interruption_point();
    }
    return true;
}

bool CMyRestrictedDB::WriteRestrictedBlock(
    const std::vector<std::pair<std::string, CNullAssetTxData>>& events,
    uint32_t blockTime, const uint256& hash)
{
    CDBBatch batch(*this);
    std::set<RestrictedEventKey> seen;
    RestrictedBlockUndo undo;
    for (const auto& event : events) {
        char prefix = 0;
        if (IsAssetNameAQualifier(event.second.asset_name)) {
            prefix = MY_TAGGED_ADDRESSES;
        } else if (IsAssetNameAnRestricted(event.second.asset_name)) {
            prefix = MY_RESTRICTED_ADDRESSES;
        }
        if (!prefix)
            continue;
        const RestrictedEventKey key(prefix, std::make_pair(event.first, event.second.asset_name));
        if (seen.insert(key).second) {
            RestrictedEventValue prior(0, 0);
            const bool existed = Read(key, prior);
            undo.emplace_back(key, std::make_pair(existed, prior));
        }
        batch.Write(key, RestrictedEventValue(event.second.flag ? 1 : 0, blockTime));
    }
    if (!undo.empty())
        batch.Write(std::make_pair(MY_RESTRICTED_UNDO, hash), undo);
    batch.Write(std::make_pair(DB_FLAG, std::string("restricted_global_index_tip_v1")), hash);
    return WriteBatch(batch);
}

bool CMyRestrictedDB::UndoRestrictedBlock(
    const std::vector<std::pair<std::string, CNullAssetTxData>>& events,
    const uint256& hash, const uint256& previousHash,
    std::vector<std::tuple<std::string, std::string, int, uint32_t>>& restored)
{
    restored.clear();
    std::set<RestrictedEventKey> expected;
    for (const auto& event : events) {
        char prefix = 0;
        if (IsAssetNameAQualifier(event.second.asset_name))
            prefix = MY_TAGGED_ADDRESSES;
        else if (IsAssetNameAnRestricted(event.second.asset_name))
            prefix = MY_RESTRICTED_ADDRESSES;
        if (prefix)
            expected.emplace(prefix, std::make_pair(event.first, event.second.asset_name));
    }

    CDBBatch batch(*this);
    if (!expected.empty()) {
        RestrictedBlockUndo undo;
        const auto undoKey = std::make_pair(MY_RESTRICTED_UNDO, hash);
        if (!Read(undoKey, undo) || undo.size() != expected.size())
            return false;
        for (const auto& item : undo) {
            if (!expected.erase(item.first))
                return false;
            if (item.second.first)
                batch.Write(item.first, item.second.second);
            else
                batch.Erase(item.first);
            restored.emplace_back(item.first.second.first, item.first.second.second,
                                  item.second.first ? item.second.second.first : -1,
                                  item.second.first ? item.second.second.second : 0);
        }
        batch.Erase(undoKey);
    }
    batch.Write(std::make_pair(DB_FLAG, std::string("restricted_global_index_tip_v1")), previousHash);
    return WriteBatch(batch);
}

bool CMyRestrictedDB::WriteRestrictedIndexTip(const uint256& hash)
{
    return Write(std::make_pair(DB_FLAG, std::string("restricted_global_index_tip_v1")), hash);
}

bool CMyRestrictedDB::ReadRestrictedIndexTip(uint256& hash)
{
    return Read(std::make_pair(DB_FLAG, std::string("restricted_global_index_tip_v1")), hash);
}

bool CMyRestrictedDB::WriteRestrictedIndexState(char state)
{
    return Write(std::make_pair(DB_FLAG, std::string("restricted_global_index_state_v1")), state);
}

bool CMyRestrictedDB::ReadRestrictedIndexState(char& state)
{
    return Read(std::make_pair(DB_FLAG, std::string("restricted_global_index_state_v1")), state);
}


bool CMyRestrictedDB::WriteFlag(const std::string &name, bool fValue)
{
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CMyRestrictedDB::ReadFlag(const std::string &name, bool &fValue)
{
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}
