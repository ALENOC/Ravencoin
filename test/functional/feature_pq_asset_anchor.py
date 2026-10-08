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
        restricted_base = 'PQRESTRICTBASE'
        node.issue(restricted_base, 1, legacy_address)
        node.issuerestrictedasset('$' + restricted_base, 1, 'true',
                                  legacy_address)
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
        root_txid = node.issue('PQROOTRECIPIENT', 10, composite_address)[0]
        root_tx = from_hex(CTransaction(), node.getrawtransaction(root_txid))
        tagged_asset_outputs = [output for output in root_tx.vout
                                if len(output.scriptPubKey) >= 32 and
                                output.scriptPubKey[-32:] == descriptor_program]
        assert_equal(len(tagged_asset_outputs), 2)
        for output in tagged_asset_outputs:
            assert_equal(output.scriptPubKey[25], ASSET_OPCODE)
        node.generate(1)
        for owned_asset, expected_balance in (('PQROOTRECIPIENT', 10),
                                              ('PQROOTRECIPIENT!', 1)):
            owned_info = node.listmyassets(owned_asset, True)[owned_asset]
            assert_equal(owned_info['balance'], expected_balance)
            assert_equal(owned_info['outpoints'][0]['txid'], root_txid)

        # Spending the issued asset must consume a funded native input with
        # the source program, even when the recipient uses a different key.
        destination_descriptor = node.getnewpqassetaddress()
        _, destination_pq = destination_descriptor.split('|')
        destination_script = bytes.fromhex(node.validateaddress(destination_pq)['scriptPubKey'])
        destination_program = destination_script[2:]
        assert_raises_rpc_error(-25, 'funded matching PQ anchor',
                                node.transfer, 'PQROOTRECIPIENT', 1,
                                destination_descriptor)
        source_anchor_txid = node.sendtoaddress(pq_part, Decimal('1'))
        node.generate(1)
        source_anchor_vout = self.output_index(
            node.getrawtransaction(source_anchor_txid),
            lambda script: script == descriptor_script)
        other_native_coins = [
            {'txid': coin['txid'], 'vout': coin['vout']}
            for coin in node.listunspent()
            if (coin['txid'], coin['vout']) !=
            (source_anchor_txid, source_anchor_vout) and not coin.get('assetName')
        ]
        assert other_native_coins
        assert_equal(node.lockunspent(False, other_native_coins), True)
        transfer_txid = node.transfer('PQROOTRECIPIENT', 1,
                                    destination_descriptor)[0]
        transfer_tx = from_hex(CTransaction(), node.getrawtransaction(transfer_txid))
        anchor_vin = [index for index, txin in enumerate(transfer_tx.vin)
                      if txin.prevout.hash == int(source_anchor_txid, 16) and
                      txin.prevout.n == source_anchor_vout]
        assert_equal(len(anchor_vin), 1)
        assert_equal(len(transfer_tx.wit.vtxinwit[anchor_vin[0]].scriptWitness.stack), 2)
        transferred = [output for output in transfer_tx.vout
                       if len(output.scriptPubKey) > 57 and
                       output.scriptPubKey[25] == ASSET_OPCODE and
                       output.scriptPubKey[-32:] == destination_program]
        assert_equal(len(transferred), 1)
        protected_change = [output for output in transfer_tx.vout
                            if len(output.scriptPubKey) > 57 and
                            output.scriptPubKey[25] == ASSET_OPCODE and
                            output.scriptPubKey[-32:] == descriptor_program]
        assert_equal(len(protected_change), 1)
        node.generate(1)
        assert_equal(node.listmyassets('PQROOTRECIPIENT', True)
                     ['PQROOTRECIPIENT']['balance'], 10)

        # Reissuance must protect both the newly created units and the
        # returned owner token. The owner return stays with its original
        # classical/PQ key pair, even when new units use a different pair.
        assert_raises_rpc_error(-5, 'canonical classical|PQ asset destination',
                                node.reissue, 'PQROOTRECIPIENT', 2,
                                legacy_address)
        assert_raises_rpc_error(-4, 'funded matching PQ anchor',
                                node.reissue, 'PQROOTRECIPIENT', 2,
                                destination_descriptor)
        reissue_anchor_txid = node.sendtoaddress(pq_part, Decimal('1'))
        node.generate(1)
        reissue_anchor_vout = self.output_index(
            node.getrawtransaction(reissue_anchor_txid),
            lambda script: script == descriptor_script)
        reissue_txid = node.reissue('PQROOTRECIPIENT', 2,
                                   destination_descriptor)[0]
        reissue_tx = from_hex(CTransaction(), node.getrawtransaction(reissue_txid))
        reissue_anchor_vin = [index for index, txin in enumerate(reissue_tx.vin)
                              if txin.prevout.hash == int(reissue_anchor_txid, 16) and
                              txin.prevout.n == reissue_anchor_vout]
        assert_equal(len(reissue_anchor_vin), 1)
        assert_equal(len(reissue_tx.wit.vtxinwit[reissue_anchor_vin[0]]
                         .scriptWitness.stack), 2)
        assert_equal(sum(output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == destination_program
                         for output in reissue_tx.vout if len(output.scriptPubKey) > 57), 1)
        classical_script = bytes.fromhex(
            node.validateaddress(classical_part)['scriptPubKey'])
        assert_equal(sum(output.scriptPubKey[:25] == classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == descriptor_program
                         for output in reissue_tx.vout if len(output.scriptPubKey) > 57), 1)
        node.generate(1)
        assert_equal(node.listmyassets('PQROOTRECIPIENT', True)
                     ['PQROOTRECIPIENT']['balance'], 12)
        assert_equal(node.listmyassets('PQROOTRECIPIENT!', True)
                     ['PQROOTRECIPIENT!']['balance'], 1)

        # A subasset uses the root owner token as authority. Its return and
        # the new subasset and sub-owner outputs must all remain tagged.
        sub_name = 'PQROOTRECIPIENT/SUB'
        assert_raises_rpc_error(-4, 'funded matching PQ anchor',
                                node.issue, sub_name, 3,
                                destination_descriptor)
        sub_anchor_txid = node.sendtoaddress(pq_part, Decimal('1'))
        node.generate(1)
        sub_anchor_vout = self.output_index(
            node.getrawtransaction(sub_anchor_txid),
            lambda script: script == descriptor_script)
        sub_issue_txid = node.issue(sub_name, 3, destination_descriptor)[0]
        sub_issue = from_hex(CTransaction(), node.getrawtransaction(sub_issue_txid))
        sub_anchor_vin = [index for index, txin in enumerate(sub_issue.vin)
                          if txin.prevout.hash == int(sub_anchor_txid, 16) and
                          txin.prevout.n == sub_anchor_vout]
        assert_equal(len(sub_anchor_vin), 1)
        assert_equal(len(sub_issue.wit.vtxinwit[sub_anchor_vin[0]]
                         .scriptWitness.stack), 2)
        assert_equal(sum(output.scriptPubKey[:25] == classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == descriptor_program
                         for output in sub_issue.vout
                         if len(output.scriptPubKey) > 57), 1)
        assert_equal(sum(output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == destination_program
                         for output in sub_issue.vout
                         if len(output.scriptPubKey) > 57), 2)
        node.generate(1)
        assert_equal(node.listmyassets(sub_name, True)[sub_name]['balance'], 3)
        assert_equal(node.listmyassets(sub_name + '!', True)
                     [sub_name + '!']['balance'], 1)

        # A batched unique issue returns the same protected parent owner
        # token while placing every unique asset under the recipient program.
        assert_raises_rpc_error(-4, 'funded matching PQ anchor',
                                node.issueunique, 'PQROOTRECIPIENT',
                                ['first', 'second'], None,
                                destination_descriptor)
        unique_anchor_txid = node.sendtoaddress(pq_part, Decimal('1'))
        node.generate(1)
        unique_anchor_vout = self.output_index(
            node.getrawtransaction(unique_anchor_txid),
            lambda script: script == descriptor_script)
        unique_txid = node.issueunique(
            'PQROOTRECIPIENT', ['first', 'second'], None,
            destination_descriptor)[0]
        unique_tx = from_hex(CTransaction(), node.getrawtransaction(unique_txid))
        unique_anchor_vin = [index for index, txin in enumerate(unique_tx.vin)
                             if txin.prevout.hash == int(unique_anchor_txid, 16) and
                             txin.prevout.n == unique_anchor_vout]
        assert_equal(len(unique_anchor_vin), 1)
        assert_equal(len(unique_tx.wit.vtxinwit[unique_anchor_vin[0]]
                         .scriptWitness.stack), 2)
        assert_equal(sum(output.scriptPubKey[:25] == classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == descriptor_program
                         for output in unique_tx.vout
                         if len(output.scriptPubKey) > 57), 1)
        assert_equal(sum(output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == destination_program
                         for output in unique_tx.vout
                         if len(output.scriptPubKey) > 57), 2)
        node.generate(1)
        for tag in ('first', 'second'):
            unique_name = 'PQROOTRECIPIENT#' + tag
            assert_equal(node.listmyassets(unique_name, True)
                         [unique_name]['balance'], 1)

        # A legacy root owner can first be migrated to a protected output.
        # The restricted-asset reissue then returns that protected owner token.
        # A nontrivial qualifier verifier still needs separate coverage.
        assert_equal(node.lockunspent(True), True)
        assert_raises_rpc_error(-4, 'migrate the legacy authority first',
                                node.reissuerestrictedasset,
                                '$' + restricted_base, 1,
                                destination_descriptor)
        migrate_owner_txid = node.transfer(
            restricted_base + '!', 1, composite_address)[0]
        node.generate(1)
        migrated_owner = from_hex(
            CTransaction(), node.getrawtransaction(migrate_owner_txid))
        assert_equal(sum(output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == descriptor_program
                         for output in migrated_owner.vout
                         if len(output.scriptPubKey) > 57), 1)
        restricted_anchor_txid = node.sendtoaddress(pq_part, Decimal('1'))
        node.generate(1)
        restricted_anchor_vout = self.output_index(
            node.getrawtransaction(restricted_anchor_txid),
            lambda script: script == descriptor_script)
        available_restricted_anchors = {
            (coin['txid'], coin['vout']) for coin in node.listunspent()
            if coin['scriptPubKey'] == descriptor_script.hex()
        }
        assert (restricted_anchor_txid, restricted_anchor_vout) in available_restricted_anchors
        restricted_reissue_txid = node.reissuerestrictedasset(
            '$' + restricted_base, 1, destination_descriptor)[0]
        restricted_reissue = from_hex(
            CTransaction(), node.getrawtransaction(restricted_reissue_txid))
        restricted_anchor_vin = [index for index, txin in
                                 enumerate(restricted_reissue.vin)
                                 if (format(txin.prevout.hash, '064x'),
                                     txin.prevout.n) in available_restricted_anchors]
        assert_equal(len(restricted_anchor_vin), 1)
        assert_equal(len(restricted_reissue.wit.vtxinwit[restricted_anchor_vin[0]]
                         .scriptWitness.stack), 2)
        assert_equal(sum(output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == destination_program
                         for output in restricted_reissue.vout
                         if len(output.scriptPubKey) > 57), 1)
        assert_equal(sum(output.scriptPubKey[:25] == classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == descriptor_program
                         for output in restricted_reissue.vout
                         if len(output.scriptPubKey) > 57), 1)
        node.generate(1)
        assert_equal(node.listmyassets('$' + restricted_base, True)
                     ['$' + restricted_base]['balance'], 2)

        # Owner tokens use the same protected transfer and anchor rules.
        assert_raises_rpc_error(-25, 'funded matching PQ anchor',
                                node.transfer, 'PQROOTRECIPIENT!', 1,
                                destination_descriptor)
        assert_equal(node.lockunspent(True), True)
        node.sendtoaddress(pq_part, Decimal('1'))
        node.generate(1)
        owner_transfer_txid = node.transfer(
            'PQROOTRECIPIENT!', 1, destination_descriptor)[0]
        owner_transfer = from_hex(
            CTransaction(), node.getrawtransaction(owner_transfer_txid))
        owner_outputs = [
            output for output in owner_transfer.vout
            if len(output.scriptPubKey) > 57 and
            output.scriptPubKey[25] == ASSET_OPCODE and
            output.scriptPubKey[-32:] == destination_program
        ]
        assert_equal(len(owner_outputs), 1)
        node.generate(1)
        assert_equal(node.listmyassets('PQROOTRECIPIENT!', True)
                     ['PQROOTRECIPIENT!']['balance'], 1)

        # An explicit asset change descriptor must preserve its own PQ key.
        assert_equal(node.lockunspent(True), True)
        node.sendtoaddress(pq_part, Decimal('1'))
        node.sendtoaddress(destination_pq, Decimal('1'))
        node.generate(1)
        explicit_change = node.getnewpqassetaddress()
        _, explicit_change_pq = explicit_change.split('|')
        explicit_change_script = bytes.fromhex(
            node.validateaddress(explicit_change_pq)['scriptPubKey'])
        next_destination = node.getnewpqassetaddress()
        explicit_transfer_txid = node.transfer(
            'PQROOTRECIPIENT', 4, next_destination, '', 0, '', explicit_change)[0]
        explicit_transfer = from_hex(
            CTransaction(), node.getrawtransaction(explicit_transfer_txid))
        explicit_change_outputs = [
            output for output in explicit_transfer.vout
            if len(output.scriptPubKey) > 57 and
            output.scriptPubKey[25] == ASSET_OPCODE and
            output.scriptPubKey[-32:] == explicit_change_script[2:]
        ]
        assert_equal(len(explicit_change_outputs), 1)
        node.generate(1)
        assert_equal(node.listmyassets('PQROOTRECIPIENT', True)
                     ['PQROOTRECIPIENT']['balance'], 12)

        # A root qualifier has no parent authority input but its output must
        # still carry the recipient's canonical PQ program.
        assert_equal(node.lockunspent(True), True)
        qualifier_name = '#PQQUALROOT'
        qualifier_txid = node.issuequalifierasset(
            qualifier_name, 1, destination_descriptor)[0]
        qualifier_tx = from_hex(
            CTransaction(), node.getrawtransaction(qualifier_txid))
        assert_equal(sum(output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == destination_program
                         for output in qualifier_tx.vout
                         if len(output.scriptPubKey) > 57), 1)
        node.generate(1)
        assert_equal(node.listmyassets(qualifier_name, True)
                     [qualifier_name]['balance'], 1)

        # Restricted issuance is authorized by ROOT!, not by $ROOT!.
        # That owner token now uses the destination program after transfer.
        node.sendtoaddress(destination_pq, Decimal('1'))
        node.generate(1)
        available_issue_anchors = {
            (coin['txid'], coin['vout']) for coin in node.listunspent()
            if coin['scriptPubKey'] == destination_script.hex()
        }
        assert available_issue_anchors
        restricted_issue_name = '$PQROOTRECIPIENT'
        restricted_issue_txid = node.issuerestrictedasset(
            restricted_issue_name, 1, 'true', composite_address)[0]
        restricted_issue = from_hex(
            CTransaction(), node.getrawtransaction(restricted_issue_txid))
        issue_anchor_vin = [index for index, txin in enumerate(restricted_issue.vin)
                            if (format(txin.prevout.hash, '064x'),
                                txin.prevout.n) in available_issue_anchors]
        assert_equal(len(issue_anchor_vin), 1)
        assert_equal(len(restricted_issue.wit.vtxinwit[issue_anchor_vin[0]]
                         .scriptWitness.stack), 2)
        assert_equal(sum(output.scriptPubKey[:25] == classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == descriptor_program
                         for output in restricted_issue.vout
                         if len(output.scriptPubKey) > 57), 1)
        destination_classical, _ = destination_descriptor.split('|')
        destination_classical_script = bytes.fromhex(
            node.validateaddress(destination_classical)['scriptPubKey'])
        assert_equal(sum(output.scriptPubKey[:25] == destination_classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == destination_program
                         for output in restricted_issue.vout
                         if len(output.scriptPubKey) > 57), 1)
        node.generate(1)
        assert_equal(node.listmyassets(restricted_issue_name, True)
                     [restricted_issue_name]['balance'], 1)

        # A sub-qualifier returns its parent qualifier authority, not an
        # owner token, under the parent key's existing PQ program.
        node.sendtoaddress(destination_pq, Decimal('1'))
        node.generate(1)
        available_qualifier_anchors = {
            (coin['txid'], coin['vout']) for coin in node.listunspent()
            if coin['scriptPubKey'] == destination_script.hex()
        }
        assert available_qualifier_anchors
        sub_qualifier_name = '#PQQUALROOT/#SUB'
        sub_qualifier_txid = node.issuequalifierasset(
            sub_qualifier_name, 1, composite_address)[0]
        sub_qualifier_tx = from_hex(
            CTransaction(), node.getrawtransaction(sub_qualifier_txid))
        qualifier_anchor_vin = [index for index, txin in
                                enumerate(sub_qualifier_tx.vin)
                                if (format(txin.prevout.hash, '064x'),
                                    txin.prevout.n) in available_qualifier_anchors]
        assert_equal(len(qualifier_anchor_vin), 1)
        assert_equal(len(sub_qualifier_tx.wit.vtxinwit[qualifier_anchor_vin[0]]
                         .scriptWitness.stack), 2)
        assert_equal(sum(output.scriptPubKey[:25] == destination_classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == destination_program
                         for output in sub_qualifier_tx.vout
                         if len(output.scriptPubKey) > 57), 1)
        assert_equal(sum(output.scriptPubKey[:25] == classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == descriptor_program
                         for output in sub_qualifier_tx.vout
                         if len(output.scriptPubKey) > 57), 1)
        node.generate(1)
        assert_equal(node.listmyassets(qualifier_name, True)
                     [qualifier_name]['balance'], 1)
        assert_equal(node.listmyassets(sub_qualifier_name, True)
                     [sub_qualifier_name]['balance'], 1)

        # The dedicated qualifier transfer RPC must use the same protected
        # asset transfer builder as a normal asset send.
        node.sendtoaddress(destination_pq, Decimal('1'))
        node.generate(1)
        available_transfer_anchors = {
            (coin['txid'], coin['vout']) for coin in node.listunspent()
            if coin['scriptPubKey'] == destination_script.hex()
        }
        assert available_transfer_anchors
        qualifier_transfer_txid = node.transferqualifier(
            qualifier_name, 1, composite_address)[0]
        qualifier_transfer = from_hex(
            CTransaction(), node.getrawtransaction(qualifier_transfer_txid))
        qualifier_transfer_anchor_vin = [index for index, txin in
                                         enumerate(qualifier_transfer.vin)
                                         if (format(txin.prevout.hash, '064x'),
                                             txin.prevout.n) in available_transfer_anchors]
        assert_equal(len(qualifier_transfer_anchor_vin), 1)
        assert_equal(len(qualifier_transfer.wit.vtxinwit[
            qualifier_transfer_anchor_vin[0]].scriptWitness.stack), 2)
        assert_equal(sum(output.scriptPubKey[:25] == classical_script and
                         output.scriptPubKey[25] == ASSET_OPCODE and
                         output.scriptPubKey[-32:] == descriptor_program
                         for output in qualifier_transfer.vout
                         if len(output.scriptPubKey) > 57), 1)
        node.generate(1)
        assert_equal(node.listmyassets(qualifier_name, True)
                     [qualifier_name]['balance'], 1)


if __name__ == '__main__':
    PQAssetAnchorTest().main()
