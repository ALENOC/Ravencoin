#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Restricted-asset blocks must use the candidate parent's bit-7 state."""

import configparser
import os

from test_framework import util as test_util
from test_framework.blocktools import create_block, create_coinbase
from test_framework.mininode import CTransaction, from_hex
from test_framework.test_framework import RavenTestFramework
from test_framework.util import Decimal, assert_equal, assert_raises_rpc_error


ASSETS_ONLY_VERSION = 0x30000040
ASSETS_AND_RIP5_VERSION = 0x300000c0


class Rip5ActivationReorgTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-assetindex', '-persistmempool=0',
                            '-blockversion={}'.format(ASSETS_ONLY_VERSION)]]

    def rip5_status(self, node):
        return node.getblockchaininfo()['bip9_softforks']['messaging_restricted']['status']

    def issue_raw(self, node, asset_name):
        native_coin = next(coin for coin in node.listunspent()
                           if coin['amount'] > 1501 and coin['confirmations'] > 101)
        owner_name = asset_name[1:] + '!'
        owner_coin = node.listmyassets(owner_name, True)[owner_name]['outpoints'][0]
        raw = node.createrawtransaction(
            [{'txid': native_coin['txid'], 'vout': native_coin['vout']},
             {'txid': owner_coin['txid'], 'vout': owner_coin['vout']}],
            {'n1issueRestrictedXXXXXXXXXXXXZVT9V': 1500,
             node.getnewaddress(): native_coin['amount'] - Decimal('1500.1'),
             node.getnewaddress(): {'issue_restricted': {
                 'asset_name': asset_name, 'asset_quantity': 1,
                 'verifier_string': 'true', 'units': 0,
                 'reissuable': 1, 'has_ipfs': 0}}})
        signed = node.signrawtransaction(raw)
        assert_equal(signed['complete'], True)
        return signed['hex']

    def run_test(self):
        node = self.nodes[0]
        activation_height = 576
        node.generate(287)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'locked_in')
        assert_equal(self.rip5_status(node), 'started')
        # Signal bit 6 alone in the first STARTED period. Signal bit 7 in
        # the next one so assets are active before restricted assets.
        self.restart_node(0, ['-assetindex', '-persistmempool=0',
                              '-blockversion={}'.format(ASSETS_AND_RIP5_VERSION)])
        node = self.nodes[0]
        node.generate(activation_height - 3 - node.getblockcount())
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'active')
        assert_equal(self.rip5_status(node), 'locked_in')
        base_name = 'RIP5BOUNDARY'
        restricted_name = '$' + base_name
        base_txid = node.issue(base_name, 1)[0]
        base_block = node.generate(1)[0]
        assert_equal(node.getblockcount(), activation_height - 2)
        assert base_txid in node.getblock(base_block)['tx']
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'active')
        assert_equal(self.rip5_status(node), 'locked_in')

        original_pre_activation = node.generate(1)[0]
        node.generate(1)
        assert_equal(node.getblockcount(), activation_height)
        assert_equal(self.rip5_status(node), 'active')
        assert_equal(node.listglobalrestrictions(), [])
        raw = self.issue_raw(node, restricted_name)
        txid = node.decoderawtransaction(raw)['txid']
        assert_equal(node.testmempoolaccept([raw])[0]['allowed'], True)

        # Rewind to H-2. A competing H-1 block must reject the same valid
        # transaction even though this process has already reached ACTIVE.
        node.invalidateblock(original_pre_activation)
        assert_equal(node.getbestblockhash(), base_block)
        assert_equal(self.rip5_status(node), 'locked_in')
        assert_raises_rpc_error(-1, 'Restricted assets must be active',
                                node.listglobalrestrictions)
        early_result = node.testmempoolaccept([raw])[0]
        assert_equal(early_result['allowed'], False)
        assert_equal(early_result['reject-reason'],
                     '16: bad-tx-null-asset-data-before-restricted-assets-activated')

        config = configparser.ConfigParser()
        config.read(self.options.configfile)
        test_util.x16r_hash_cmd = os.path.join(
            config['environment']['BUILDDIR'], 'src', 'test',
            'test_raven_hash' + config['environment']['EXEEXT'])
        block = create_block(int(base_block, 16), create_coinbase(activation_height - 1),
                             node.getblockheader(base_block)['time'] + 1)
        block.nVersion = node.getblockheader(original_pre_activation)['version']
        block.vtx.append(from_hex(CTransaction(), raw))
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()),
                     'bad-tx-null-asset-data-before-restricted-assets-activated')
        assert_equal(node.getbestblockhash(), base_block)

        # Mempool admission at H-1 targets H, the first active block.
        pre_activation = node.generate(1)[0]
        assert_equal(node.getblockcount(), activation_height - 1)
        assert_equal(self.rip5_status(node), 'active')
        assert_equal(node.testmempoolaccept([raw])[0]['allowed'], True)
        assert_equal(node.sendrawtransaction(raw), txid)
        activation_block = node.generate(1)[0]
        assert_equal(node.getblockcount(), activation_height)
        assert txid in node.getblock(activation_block)['tx']
        assert_equal(node.getassetdata(restricted_name)['amount'], 1)
        post_activation = node.generate(1)[0]
        assert_equal(node.getblockcount(), activation_height + 1)
        assert_equal(self.rip5_status(node), 'active')
        assert_equal(node.verifychain(4, 4), True)

        # Disconnect both sides of the boundary and restart while the old
        # rules apply. Reconsidering the saved branch must restore the asset.
        node.invalidateblock(pre_activation)
        assert_equal(node.getbestblockhash(), base_block)
        assert_equal(node.getassetdata(restricted_name), None)
        assert_equal(self.rip5_status(node), 'locked_in')
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'active')
        assert_raises_rpc_error(-1, 'Restricted assets must be active',
                                node.listglobalrestrictions)
        assert_equal(node.testmempoolaccept([raw])[0]['reject-reason'],
                     early_result['reject-reason'])
        self.restart_node(0, ['-assetindex', '-persistmempool=0',
                              '-blockversion={}'.format(ASSETS_AND_RIP5_VERSION)])
        node = self.nodes[0]
        assert_equal(node.getbestblockhash(), base_block)
        assert_equal(self.rip5_status(node), 'locked_in')
        assert_raises_rpc_error(-1, 'Restricted assets must be active',
                                node.listglobalrestrictions)
        assert_equal(node.testmempoolaccept([raw])[0]['reject-reason'],
                     early_result['reject-reason'])
        node.reconsiderblock(pre_activation)
        assert_equal(node.getbestblockhash(), post_activation)
        assert_equal(node.getblockcount(), activation_height + 1)
        assert txid in node.getblock(activation_block)['tx']
        assert_equal(node.getassetdata(restricted_name)['amount'], 1)
        assert_equal(node.listglobalrestrictions(), [])
        assert_equal(node.verifychain(4, 4), True)


if __name__ == '__main__':
    Rip5ActivationReorgTest().main()
