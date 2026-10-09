#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Exercise protected asset source selection in the alternate transfer RPCs."""

from decimal import Decimal

from test_framework.mininode import CTransaction, from_hex
from test_framework.test_framework import RavenTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


ASSET_OPCODE = 0xc0


class PQAssetSourceRPCTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-assetindex', '-vbparams=pq_assets:0:999999999999']]

    @staticmethod
    def assert_protected_transfer(node, txid, source_program, destination_program):
        transaction = from_hex(CTransaction(), node.getrawtransaction(txid))
        programs = [output.scriptPubKey[-32:] for output in transaction.vout
                    if len(output.scriptPubKey) > 57 and
                    output.scriptPubKey[25] == ASSET_OPCODE]
        assert_equal(programs.count(source_program), 1)
        assert_equal(programs.count(destination_program), 1)
        assert any(len(witness.scriptWitness.stack) == 2
                   for witness in transaction.wit.vtxinwit)

    @staticmethod
    def asset_output_programs(node, txid):
        transaction = from_hex(CTransaction(), node.getrawtransaction(txid))
        return [output.scriptPubKey[-32:] for output in transaction.vout
                if len(output.scriptPubKey) > 57 and
                output.scriptPubKey[25] == ASSET_OPCODE]

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.listpqassetaddresses(),
                     {'active': False, 'addresses': []})
        legacy_address = node.getnewaddress()
        node.generate(861)
        node.issue('PQSOURCELEGACY', 1, legacy_address)
        node.issue('PQSOURCELEGACY2', 1, legacy_address)
        node.issue('PQSOURCEPARTIAL', 3, legacy_address)
        node.generate(2)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['pq_assets']['status'],
                     'active')

        source = node.getnewpqassetaddress()
        source_classical, source_pq = source.split('|')
        source_program = bytes.fromhex(
            node.validateaddress(source_pq)['scriptPubKey'])[2:]
        destination = node.getnewpqassetaddress()
        _, destination_pq = destination.split('|')
        destination_program = bytes.fromhex(
            node.validateaddress(destination_pq)['scriptPubKey'])[2:]
        assert_equal(node.listpqassetaddresses()['active'], True)
        assert_equal(set(node.listpqassetaddresses()['addresses']),
                     {source, destination})
        self.restart_node(0, self.extra_args[0])
        assert_equal(node.listpqassetaddresses()['active'], True)
        assert_equal(set(node.listpqassetaddresses()['addresses']),
                     {source, destination})

        # A confirmed legacy asset and its owner token can move in full to
        # tagged outputs after activation without a PQ anchor on the old input.
        migrated_asset = node.transferfromaddress(
            'PQSOURCELEGACY', legacy_address, 1, destination)[0]
        migrated_second = node.transferfromaddresses(
            'PQSOURCELEGACY2', [legacy_address], 1, destination)[0]
        migrated_owner = node.transfer(
            'PQSOURCELEGACY!', 1, destination)[0]
        for txid in (migrated_asset, migrated_second, migrated_owner):
            assert_equal(self.asset_output_programs(node, txid),
                         [destination_program])

        # Sending part of one historical UTXO must not create classical-only
        # change. The RPC can migrate the remainder with explicit PQ change.
        assert_raises_rpc_error(
            -25, 'Active PQ asset change requires a protected source or explicit PQ change destination',
            node.transferfromaddress, 'PQSOURCEPARTIAL', legacy_address, 1,
            destination)
        partial_txid = node.transferfromaddress(
            'PQSOURCEPARTIAL', legacy_address, 1, destination,
            '', 0, '', source)[0]
        assert_equal(sorted(self.asset_output_programs(node, partial_txid)),
                     sorted([source_program, destination_program]))
        node.generate(1)
        assert_equal(node.listmyassets('PQSOURCEPARTIAL', True)
                     ['PQSOURCEPARTIAL']['balance'], 3)
        assert_raises_rpc_error(
            -25, 'funded matching PQ anchor',
            node.transferfromaddress, 'PQSOURCEPARTIAL', source, 1,
            destination, '', 0, '', source)
        node.sendtoaddress(source_pq, Decimal('1'))
        node.generate(1)
        node.transferfromaddress('PQSOURCEPARTIAL', source, 1,
                                 destination, '', 0, '', source)
        node.generate(1)

        node.issue('PQSOURCEACTIVE', 5, source)
        node.generate(1)
        node.sendtoaddress(source_pq, Decimal('1'))
        node.generate(1)

        # The classical part alone or a different PQ key must not select a
        # post-activation output, even though both keys are in this wallet.
        wrong_source = source_classical + '|' + node.getnewpqaddress()
        for selected in (source_classical, wrong_source):
            assert_raises_rpc_error(
                -8, 'No asset outpoints are selected',
                node.transferfromaddress, 'PQSOURCEACTIVE', selected, 2,
                destination, '', 0, '', source)
            assert_raises_rpc_error(
                -8, 'No asset outpoints are selected',
                node.transferfromaddresses, 'PQSOURCEACTIVE', [selected], 2,
                destination, '', 0, '', source)

        assert_raises_rpc_error(
            -5, 'canonical classical|PQ asset destination',
            node.transferfromaddress, 'PQSOURCEACTIVE', source, 2,
            destination, '', 0, '', source_classical)
        assert_raises_rpc_error(
            -5, 'canonical classical|PQ asset destination',
            node.transferfromaddresses, 'PQSOURCEACTIVE', [source], 2,
            destination, '', 0, '', source_classical)

        first_txid = node.transferfromaddress(
            'PQSOURCEACTIVE', source, 2, destination, '', 0, '', source)[0]
        self.assert_protected_transfer(
            node, first_txid, source_program, destination_program)
        node.generate(1)

        node.sendtoaddress(source_pq, Decimal('1'))
        node.generate(1)
        second_txid = node.transferfromaddresses(
            'PQSOURCEACTIVE', [wrong_source, source], 1,
            destination, '', 0, '', source)[0]
        self.assert_protected_transfer(
            node, second_txid, source_program, destination_program)
        node.generate(1)
        assert_equal(node.listmyassets('PQSOURCEACTIVE', True)
                     ['PQSOURCEACTIVE']['balance'], 5)

        # The address index combines protected outputs that share a
        # classical key, even though their PQ programs differ. Its address
        # row is not a valid active asset destination.
        second_pq = node.getnewpqaddress()
        second_pair = source_classical + '|' + second_pq
        second_program = bytes.fromhex(
            node.validateaddress(second_pq)['scriptPubKey'])[2:]
        assert second_program != source_program
        index_asset = 'PQINDEXSHARED'
        node.issue(index_asset, 2, source)
        node.sendtoaddress(source_pq, Decimal('1'))
        node.generate(1)
        split_txid = node.transferfromaddress(
            index_asset, source, 1, second_pair, '', 0, '', source)[0]
        assert_equal(sorted(self.asset_output_programs(node, split_txid)),
                     sorted([source_program, second_program]))
        node.generate(1)
        assert_equal(node.listmyassets(index_asset, True)
                     [index_asset]['balance'], 2)
        assert_equal(node.listaddressesbyasset(index_asset),
                     {source_classical: 2})
        assert_equal(node.listassetbalancesbyaddress(source_classical)
                     [index_asset], 2)
        assert_raises_rpc_error(-5, 'Invalid Raven address',
                                node.listassetbalancesbyaddress,
                                second_pair)
        assert_raises_rpc_error(
            -5, 'canonical classical|PQ asset destination',
            node.transferfromaddress, index_asset, source, 1,
            source_classical)


if __name__ == '__main__':
    PQAssetSourceRPCTest().main()
