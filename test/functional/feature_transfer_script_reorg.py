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
        self.extra_args = [['-assetindex', '-persistmempool=0']]

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

        node.generate(287)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'locked_in')
        locked_in_tip = node.getbestblockhash()
        issue_txid = node.issue(asset_name, 2)[0]
        active_block = None
        for _ in range(300):
            candidate = node.generate(1)[0]
            if node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'] == 'active':
                active_block = candidate
                break
        assert active_block is not None
        issue_block = active_block
        assert_equal(node.getblockcount(), 863)
        assert issue_txid in node.getblock(issue_block)['tx']
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'active')
        active_result = node.testmempoolaccept([raw])[0]
        assert_equal(active_result['reject-reason'], 'missing-inputs')

        transfer_txid = node.transfer(asset_name, 1, node.getnewaddress(), 'ab' * 32, 123456789)[0]
        transfer_block = node.generate(1)[0]
        assert_equal(node.getblockcount(), 864)
        assert transfer_txid in node.getblock(transfer_block)['tx']
        transfer_tx = next(tx for tx in node.getblock(transfer_block, 2)['tx'] if tx['txid'] == transfer_txid)
        assert any(vin['txid'] == issue_txid for vin in transfer_tx['vin'])
        message_outputs = [vout['scriptPubKey'] for vout in transfer_tx['vout']
                           if vout['scriptPubKey'].get('asset', {}).get('message') == 'ab' * 32]
        assert_equal(len(message_outputs), 1)
        assert_equal(message_outputs[0]['asset']['name'], asset_name)
        assert_equal(message_outputs[0]['asset']['amount'], 1)
        assert_equal(message_outputs[0]['asset']['expire_time'], 123456789)
        assert_equal(message_outputs[0]['hex'][52:54], '4c')
        # Recheck blocks on both sides of the activation boundary.
        assert_equal(node.verifychain(4, 4), True)

        node.invalidateblock(active_block)
        assert_equal(node.getbestblockhash(), locked_in_tip)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'locked_in')
        live_result = node.testmempoolaccept([raw])[0]

        self.stop_node(0)
        self.start_node(0, ['-assetindex', '-persistmempool=0'])
        node = self.nodes[0]
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'locked_in')
        restarted_result = node.testmempoolaccept([raw])[0]
        assert_equal(live_result['reject-reason'], restarted_result['reject-reason'])

        node.reconsiderblock(active_block)
        assert_equal(node.getbestblockhash(), transfer_block)
        assert_equal(node.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'active')
        assert_equal(node.verifychain(4, 4), True)


if __name__ == '__main__':
    TransferScriptReorgTest().main()
