#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Exercise the separate RIP-25 asset deployment boundary on regtest."""

from test_framework.test_framework import RavenTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class PQAssetDeploymentTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-vbparams=pq_assets:0:999999999999']]

    def run_test(self):
        node = self.nodes[0]

        node.generate(143)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['pq_assets']['status'], 'started')
        node.generate(144)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['pq_assets']['status'], 'locked_in')
        node.generate(144)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['pq_assets']['status'], 'active')

        # Core's asset deployment becomes active at the following boundary.
        node.generate(1)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['assets']['status'], 'active')
        assert_raises_rpc_error(None, 'bad-pq-asset-output', node.issue,
                                'PQ_BOUNDARY', 1, node.getnewaddress())

        first_locked_in_block = node.getblockhash(288)
        node.invalidateblock(first_locked_in_block)
        assert_equal(node.getblockcount(), 287)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['pq_assets']['status'], 'locked_in')
        node.reconsiderblock(first_locked_in_block)
        assert_equal(node.getblockcount(), 432)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['pq_assets']['status'], 'active')
        assert_raises_rpc_error(None, 'bad-pq-asset-output', node.issue,
                                'PQ_BOUNDARY_2', 1, node.getnewaddress())


if __name__ == '__main__':
    PQAssetDeploymentTest().main()
