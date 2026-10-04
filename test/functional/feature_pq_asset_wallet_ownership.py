#!/usr/bin/env python3
# Copyright (c) 2026 The Raven Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Do not report a bit13 asset as spendable without its matching PQ key."""

from decimal import Decimal

from test_framework.mininode import CTransaction, from_hex, to_hex
from test_framework.test_framework import RavenTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


ASSET_OPCODE = 0xc0
DROP_OPCODE = 0x75


class PQAssetWalletOwnershipTest(RavenTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ['-assetindex', '-vbparams=pq_assets:0:999999999999'],
            ['-assetindex', '-vbparams=pq_assets:0:999999999999'],
        ]

    @staticmethod
    def tag_asset_outputs(raw, program, expected_count):
        tx = from_hex(CTransaction(), raw)
        count = 0
        for output in tx.vout:
            script = output.scriptPubKey
            if len(script) > 31 and script[25] == ASSET_OPCODE:
                assert_equal(script[-1], DROP_OPCODE)
                output.scriptPubKey = script[:-1] + program
                count += 1
        assert_equal(count, expected_count)
        return to_hex(tx)

    def run_test(self):
        sender, recipient = self.nodes
        asset_name = 'PQWALLETOWNERSHIP'
        historical_name = 'PQHISTORICALTAG'
        sender_asset_address = sender.getnewaddress()
        recipient_asset_address = recipient.getnewaddress()
        recipient_owner_address = recipient.getnewaddress()
        historical_recipient = recipient.getnewaddress()
        pq_address = sender.getnewpqaddress()
        pq_script = bytes.fromhex(sender.validateaddress(pq_address)['scriptPubKey'])
        assert_equal(pq_script[:2], b'\x52\x20')
        assert_equal(recipient.validateaddress(pq_address)['ismine'], False)
        program = pq_script[2:]
        assert_equal(len(program), 32)

        sender.generate(860)
        self.sync_all()
        sender.issue(asset_name, 1, sender_asset_address)
        sender.issue(historical_name, 1, sender_asset_address)
        sender.generate(1)
        self.sync_all()
        assert_equal(sender.getblockcount(), 861)

        # A tag-shaped output created before the effective activation height
        # remains a legacy, classically owned asset even after activation.
        historical_outpoint = sender.listmyassets(historical_name, True)[historical_name]['outpoints'][0]
        historical_funding = next(coin for coin in sender.listunspent()
                                  if coin['amount'] > Decimal('2'))
        historical_inputs = [
            {'txid': historical_outpoint['txid'], 'vout': historical_outpoint['vout']},
            {'txid': historical_funding['txid'], 'vout': historical_funding['vout']},
        ]
        historical_outputs = {
            historical_recipient: {'transfer': {historical_name: 1}},
            sender.getnewaddress(): historical_funding['amount'] - Decimal('0.01'),
        }
        historical_raw = sender.createrawtransaction(historical_inputs, historical_outputs)
        historical_tagged = self.tag_asset_outputs(historical_raw, program, 1)
        historical_signed = sender.signrawtransaction(historical_tagged)
        assert_equal(historical_signed['complete'], True)
        sender.sendrawtransaction(historical_signed['hex'])
        sender.generate(2)
        self.sync_all()
        assert_equal(sender.getblockcount(), 863)
        assert_equal(sender.getblockchaininfo()['bip9_softforks']['pq_assets']['status'], 'active')
        assert_equal(sender.getblockchaininfo()['bip9_softforks']['transfer_script']['status'], 'active')
        assert_equal(recipient.listmyassets(historical_name, True)[historical_name]['balance'], 1)

        asset_outpoint = sender.listmyassets(asset_name, True)[asset_name]['outpoints'][0]
        owner_name = asset_name + '!'
        owner_outpoint = sender.listmyassets(owner_name, True)[owner_name]['outpoints'][0]
        native_coin = next(coin for coin in sender.listunspent()
                           if coin['amount'] > Decimal('2'))
        inputs = [
            {'txid': asset_outpoint['txid'], 'vout': asset_outpoint['vout']},
            {'txid': owner_outpoint['txid'], 'vout': owner_outpoint['vout']},
            {'txid': native_coin['txid'], 'vout': native_coin['vout']},
        ]
        outputs = {
            recipient_asset_address: {'transfer': {asset_name: 1}},
            recipient_owner_address: {'transfer': {owner_name: 1}},
            pq_address: Decimal('1'),
            sender.getnewaddress(): native_coin['amount'] - Decimal('1.01'),
        }
        migration = sender.createrawtransaction(inputs, outputs)
        tagged = self.tag_asset_outputs(migration, program, 2)
        signed = sender.signrawtransaction(tagged)
        assert_equal(signed['complete'], True)
        migration_txid = sender.sendrawtransaction(signed['hex'])
        sender.generate(1)
        self.sync_all()

        # A classical key alone is not ownership of a protected asset.
        assert_equal(recipient.listmyassets(asset_name, True), {})
        assert_equal(recipient.listmyassets(owner_name, True), {})
        assert all(bytes.fromhex(coin['scriptPubKey']) != pq_script
                   for coin in recipient.listunspent())

        # Raw classical signing is possible, but consensus still requires the
        # separate native witness-v2 anchor for each protected asset spend.
        decoded = sender.decoderawtransaction(signed['hex'])
        asset_vouts = {out['scriptPubKey']['asset']['name']: out['n']
                       for out in decoded['vout']
                       if 'asset' in out['scriptPubKey']}
        assert_equal(set(asset_vouts), {asset_name, owner_name})
        for name in (asset_name, owner_name):
            asset_input = {'txid': migration_txid, 'vout': asset_vouts[name]}
            spend = recipient.createrawtransaction(
                [{'txid': asset_input['txid'], 'vout': asset_input['vout']}],
                {recipient.getnewaddress(): {'transfer': {name: 1}}})
            spend = self.tag_asset_outputs(spend, program, 1)
            spend_signed = recipient.signrawtransaction(spend)
            assert_equal(spend_signed['complete'], True)
            assert_raises_rpc_error(-26, 'bad-pq-asset-anchor',
                                    recipient.sendrawtransaction, spend_signed['hex'])


if __name__ == '__main__':
    PQAssetWalletOwnershipTest().main()
