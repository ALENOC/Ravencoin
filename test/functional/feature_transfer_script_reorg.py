#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A bit-8 reorg must not leave transfer parsing dependent on process history."""

from test_framework.test_framework import RavenTestFramework
from test_framework.util import assert_equal


class TransferScriptReorgTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        node.generate(575)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'locked_in')

        asset_name = 'LONGASSETNAME12345678901234567'
        raw = node.createrawtransaction(
            [{'txid': '11' * 32, 'vout': 0}],
            {node.getnewaddress(): {'transferwithmessage': {
                asset_name: 1, 'message': 'ab' * 32, 'expire_time': 123456789}}})
        script = node.decoderawtransaction(raw)['vout'][0]['scriptPubKey']['hex']
        assert_equal(script[52:54], '4c')  # OP_PUSHDATA1 after P2PKH and OP_RVN_ASSET.

        active_block = None
        for _ in range(300):
            candidate = node.generate(1)[0]
            if node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'] == 'active':
                active_block = candidate
                break
        assert active_block is not None
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'active')
        active_result = node.testmempoolaccept([raw])[0]
        assert_equal(active_result['reject-reason'], 'missing-inputs')

        node.invalidateblock(active_block)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'locked_in')
        live_result = node.testmempoolaccept([raw])[0]

        self.stop_node(0)
        self.start_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'locked_in')
        restarted_result = node.testmempoolaccept([raw])[0]
        assert_equal(live_result['reject-reason'], restarted_result['reject-reason'])


if __name__ == '__main__':
    TransferScriptReorgTest().main()
