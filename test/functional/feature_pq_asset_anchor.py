#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Exercise the dependent RIP-25 asset rule with a real ML-DSA anchor spend."""

import configparser
from decimal import Decimal
import os

from test_framework.blocktools import create_block, create_coinbase
from test_framework.mininode import CTransaction, from_hex, to_hex
from test_framework.test_framework import RavenTestFramework
from test_framework import util as test_util
from test_framework.util import assert_equal, assert_raises_rpc_error


ASSET_OPCODE = 0xc0
DROP_OPCODE = 0x75


class PQAssetAnchorTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-assetindex', '-vbparams=pq_assets:0:999999999999']]

    @staticmethod
    def tagged_asset_hex(raw, program):
        tx = from_hex(CTransaction(), raw)
        tagged = 0
        for output in tx.vout:
            script = output.scriptPubKey
            if len(script) > 31 and script[25] == ASSET_OPCODE:
                assert_equal(script[-1], DROP_OPCODE)
                output.scriptPubKey = script[:-1] + program
                tagged += 1
        assert_equal(tagged, 1)
        return to_hex(tx)

    @staticmethod
    def output_index(raw, predicate):
        tx = from_hex(CTransaction(), raw)
        matches = [index for index, output in enumerate(tx.vout)
                   if predicate(output.scriptPubKey)]
        assert_equal(len(matches), 1)
        return matches[0]

    def run_test(self):
        node = self.nodes[0]
        asset_name = 'PQANCHORTEST'
        legacy_address = node.getnewaddress()
        pq_address = node.getnewpqaddress()
        pq_script = bytes.fromhex(node.validateaddress(pq_address)['scriptPubKey'])
        assert_equal(pq_script[:2], b'\x52\x20')
        program = pq_script[2:]
        assert_equal(len(program), 32)

        node.generate(861)
        node.issue(asset_name, 1, legacy_address)
        node.generate(1)
        assert_equal(node.getblockcount(), 862)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['pq_assets']['status'], 'active')
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'locked_in')
        assert_raises_rpc_error(-4, 'PQ asset rules are not active',
                                node.getnewpqassetaddress)

        node.generate(1)
        assert_equal(node.getblockcount(), 863)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'active')

        assert_raises_rpc_error(-5, 'canonical classical|PQ asset destination', node.issue,
                                'PQAFTERACTIVE', 1, legacy_address)

        # A rollback to the last pre-activation tip permits a legacy issue.
        # Reconsidering the boundary must remove that transaction from mempool.
        boundary_hash = node.getblockhash(863)
        node.invalidateblock(boundary_hash)
        assert_equal(node.getblockcount(), 862)
        rollback_txid = node.issue('PQROLLBACK', 1, legacy_address)[0]
        pending_reissue = node.reissue(asset_name, 1, legacy_address)[0]
        pending_reissue_raw = node.gettransaction(pending_reissue)['hex']
        assert rollback_txid in node.getrawmempool()
        assert pending_reissue in node.getrawmempool()
        node.reconsiderblock(boundary_hash)
        assert_equal(node.getblockcount(), 863)
        assert rollback_txid not in node.getrawmempool()
        assert pending_reissue not in node.getrawmempool()

        # A boundary eviction must also release the global reissue lock.
        # A second reissue at the old-policy tip must not be blocked by a
        # transaction that no longer exists in the mempool.
        node.invalidateblock(boundary_hash)
        assert_equal(node.getblockcount(), 862)
        replacement = from_hex(CTransaction(), pending_reissue_raw)
        replacement.nLockTime = 1
        replacement_signed = node.signrawtransaction(to_hex(replacement))
        assert_equal(replacement_signed['complete'], True)
        replacement_reissue = node.sendrawtransaction(replacement_signed['hex'])
        assert replacement_reissue != pending_reissue
        assert replacement_reissue in node.getrawmempool()
        node.reconsiderblock(boundary_hash)
        assert_equal(node.getblockcount(), 863)
        assert replacement_reissue not in node.getrawmempool()

        # A stored pre-activation issue must also fail in a candidate block
        # whose parent has the effective asset rule, not only at RPC relay.
        rollback_raw = node.gettransaction(rollback_txid)['hex']
        for txin in node.decoderawtransaction(rollback_raw)['vin']:
            assert node.gettxout(txin['txid'], txin['vout']) is not None
        config = configparser.ConfigParser()
        config.read(self.options.configfile)
        test_util.x16r_hash_cmd = os.path.join(
            config['environment']['BUILDDIR'], 'src', 'test',
            'test_raven_hash' + config['environment']['EXEEXT'])
        parent_hash = node.getbestblockhash()
        block_time = node.getblockheader(parent_hash)['time'] + 1
        invalid_block = create_block(int(parent_hash, 16), create_coinbase(864), block_time)
        invalid_block.nVersion = node.getblockheader(parent_hash)['version']
        invalid_block.vtx.append(from_hex(CTransaction(), rollback_raw))
        invalid_block.hashMerkleRoot = invalid_block.calc_merkle_root()
        invalid_block.solve()
        assert_equal(node.submitblock(invalid_block.serialize().hex()),
                     'bad-pq-asset-output')

        asset_outpoint = node.listmyassets(asset_name, True)[asset_name]['outpoints'][0]
        native_coin = next(coin for coin in node.listunspent()
                           if coin['amount'] > Decimal('2'))
        native_change = node.getnewaddress()
        migration_inputs = [
            {'txid': asset_outpoint['txid'], 'vout': asset_outpoint['vout']},
            {'txid': native_coin['txid'], 'vout': native_coin['vout']},
        ]
        migration_outputs = {
            legacy_address: {'transfer': {asset_name: 1}},
            pq_address: Decimal('1'),
            native_change: native_coin['amount'] - Decimal('1.01'),
        }
        migration_raw = node.createrawtransaction(migration_inputs, migration_outputs)
        migration_tagged = self.tagged_asset_hex(migration_raw, program)
        migration_signed = node.signrawtransaction(migration_tagged)
        assert_equal(migration_signed['complete'], True)
        migration_txid = node.sendrawtransaction(migration_signed['hex'])
        node.generate(1)
        assert_equal(node.getblockcount(), 864)
        assert_equal(node.listmyassets(asset_name, True)[asset_name]['balance'], 1)

        asset_index = self.output_index(
            migration_signed['hex'],
            lambda script: len(script) > 31 and script[25] == ASSET_OPCODE)
        anchor_index = self.output_index(
            migration_signed['hex'], lambda script: script == pq_script)
        asset_input = {'txid': migration_txid, 'vout': asset_index}
        anchor_input = {'txid': migration_txid, 'vout': anchor_index}

        no_anchor = node.createrawtransaction(
            [asset_input], {legacy_address: {'transfer': {asset_name: 1}}})
        no_anchor = node.signrawtransaction(self.tagged_asset_hex(no_anchor, program))
        assert_equal(no_anchor['complete'], True)
        assert_raises_rpc_error(-26, 'bad-pq-asset-anchor',
                                node.sendrawtransaction, no_anchor['hex'])
        parent_hash = node.getbestblockhash()
        block_time = node.getblockheader(parent_hash)['time'] + 1
        missing_anchor_block = create_block(int(parent_hash, 16),
                                            create_coinbase(865), block_time)
        missing_anchor_block.nVersion = node.getblockheader(parent_hash)['version']
        missing_anchor_block.vtx.append(from_hex(CTransaction(), no_anchor['hex']))
        missing_anchor_block.hashMerkleRoot = missing_anchor_block.calc_merkle_root()
        missing_anchor_block.solve()
        assert_equal(node.submitblock(missing_anchor_block.serialize().hex()),
                     'bad-pq-asset-anchor')

        spend_raw = node.createrawtransaction(
            [asset_input, anchor_input],
            {legacy_address: {'transfer': {asset_name: 1}},
             pq_address: Decimal('0.9')})
        spend_tagged = self.tagged_asset_hex(spend_raw, program)
        spend_signed = node.signrawtransaction(spend_tagged)
        assert_equal(spend_signed['complete'], True)
        signed_tx = from_hex(CTransaction(), spend_signed['hex'])
        assert_equal(len(signed_tx.wit.vtxinwit[1].scriptWitness.stack), 2)

        damaged = from_hex(CTransaction(), spend_signed['hex'])
        signature = bytearray(damaged.wit.vtxinwit[1].scriptWitness.stack[0])
        signature[0] ^= 1
        damaged.wit.vtxinwit[1].scriptWitness.stack[0] = bytes(signature)
        assert_raises_rpc_error(-26, 'PQ ML-DSA-44 signature verification failed',
                                node.sendrawtransaction,
                                damaged.serialize_with_witness().hex())

        spend_txid = node.sendrawtransaction(spend_signed['hex'])
        mined = node.generate(1)
        assert spend_txid in node.getblock(mined[0])['tx']

        # Wallet issuance must tag both the root asset and its owner token.
        composite_address = node.getnewpqassetaddress()
        assert_equal(composite_address.count('|'), 1)
        classical_part, pq_part = composite_address.split('|')
        assert_equal(node.validateaddress(classical_part)['ismine'], True)
        assert_equal(node.validateaddress(pq_part)['ismine'], True)
        descriptor_script = bytes.fromhex(node.validateaddress(pq_part)['scriptPubKey'])
        assert_equal(descriptor_script[:2], b'\x52\x20')
        descriptor_program = descriptor_script[2:]
        root_txid = node.issue('PQROOTRECIPIENT', 1, composite_address)[0]
        root_tx = from_hex(CTransaction(), node.getrawtransaction(root_txid))
        tagged_asset_outputs = [output for output in root_tx.vout
                                if len(output.scriptPubKey) >= 32 and
                                output.scriptPubKey[-32:] == descriptor_program]
        assert_equal(len(tagged_asset_outputs), 2)
        for output in tagged_asset_outputs:
            assert_equal(output.scriptPubKey[25], ASSET_OPCODE)
        node.generate(1)
        for owned_asset in ('PQROOTRECIPIENT', 'PQROOTRECIPIENT!'):
            owned_info = node.listmyassets(owned_asset, True)[owned_asset]
            assert_equal(owned_info['balance'], 1)
            assert_equal(owned_info['outpoints'][0]['txid'], root_txid)


if __name__ == '__main__':
    PQAssetAnchorTest().main()
