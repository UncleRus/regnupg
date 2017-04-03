#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import regnupg
import shutil
import os

import logging
regnupg.log.addHandler(logging.StreamHandler())
#regnupg.log.setLevel(logging.DEBUG)


class Test(unittest.TestCase):

    homedir = '/tmp/regnupg-test'
    message = u'Test message, тестовое сообщение'

    def setUp(self):
        try:
            shutil.rmtree(self.homedir)
        except:
            pass
        os.mkdir(self.homedir)
        self.gpg = regnupg.GnuPG(homedir=self.homedir)

    def tearDown(self):
        try:
            shutil.rmtree(self.homedir)
        except:
            pass

    def _gen_key(self, passphrase):
        return self.gpg.gen_key(self.gpg.gen_key_input({'Passphrase': passphrase}))

    def test_import_keys(self):
        res = self.gpg.import_keys_file(open('test/key.txt'))
        self.assertEqual(len(res.results), 1, 'No keys imported')
        self.assertTrue(res.results[0].imported, 'Key not imported')
        self.assertEqual(res.results[0].fingerprint, '6C74DF21146E083BB6FB07545D189C58F0250410', 'Incorrect fingerprint of imported key')
        self.assertRaises(regnupg.NoDataError, self.gpg.import_keys, 'FAKE KEY DATA')

    def test_recv_keys(self):
        res = self.gpg.recv_keys('keyserver.ubuntu.com', '3E5C1192')
        self.assertEqual(res.results[0].fingerprint, 'C47415DFF48C09645B78609416126D3A3E5C1192', 'Incorrect fingerprint of received key')

    def test_export_keys(self):
        key = self._gen_key('password')
        self.assertTrue(self.gpg.export_keys(key.fingerprint).data.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'), 'Public key not exported')
        self.assertTrue(self.gpg.export_keys(key.fingerprint, True, 'password').data.startswith('-----BEGIN PGP PRIVATE KEY BLOCK-----'), 'Private key not exported')

    def test_generate_list_keys(self):
        res = self._gen_key('password')
        self.assertIsNotNone(res.fingerprint, 'Key is not generated')
        self.assertIn(res.fingerprint, self.gpg.list_keys().keys, 'Generated public key not found')
        self.assertIn(res.fingerprint, self.gpg.list_keys(True).keys, 'Generated secret key not found')

    def test_delete_keys(self):
        key = self._gen_key('password')
        self.assertRaises(regnupg.KeyDeleteError, self.gpg.delete_keys, key.fingerprint)
        self.gpg.delete_keys(key.fingerprint, True)
        self.gpg.delete_keys(key.fingerprint)
        self.assertEqual(len(self.gpg.list_keys().keys), 0, 'Key has not been deleted')
        self.gpg.delete_keys(('fakekey1', 'fakekey2'))

    def test_sign_verify(self):
        key = self._gen_key('password')
        sign = self.gpg.sign(self.message, key.fingerprint, 'password')
        self.assertTrue(sign.data.startswith('-----BEGIN PGP SIGNED MESSAGE-----'), 'Invalid sign data')
        verify = self.gpg.verify(sign.data)
        self.assertTrue(verify.valid, 'Invalid sign')
        self.assertEqual(verify.fingerprint, key.fingerprint, 'Unexpected signer fingerprint')
        self.assertRaises(regnupg.InvalidMemberError, self.gpg.sign, self.message, 'fakefingerprint')
        self.assertRaises(regnupg.NoDataError, self.gpg.verify, 'FAKE SIGN DATA')

    def test_encrypt_decrypt(self):
        sender = self._gen_key('sender_pwd')
        receiver = self._gen_key('receiver_pwd')

        encrypted = self.gpg.encrypt(self.message, receiver.fingerprint, sender.fingerprint, 'sender_pwd', True)
        self.assertTrue(encrypted.data.startswith('-----BEGIN PGP MESSAGE-----'), 'Cannot encrypt/sign')

        decrypted = self.gpg.decrypt(encrypted.data, 'receiver_pwd', sender.fingerprint)
        self.assertEqual(decrypted.data, self.message)

        self.assertRaises(regnupg.InvalidMemberError, self.gpg.encrypt, self.message, 'fake_receiver', sender.fingerprint, 'sender_pwd')

        self.gpg.delete_keys(sender.fingerprint, True)
        self.gpg.delete_keys(sender.fingerprint)

        self.assertRaises(regnupg.GpgKeyError, self.gpg.decrypt, encrypted.data, 'receiver_pwd', sender.fingerprint)

    def test_big_files(self):
        sender = self._gen_key('sender_pwd')
        receiver = self._gen_key('receiver_pwd')

        encrypted = self.gpg.encrypt(open('/tmp/bigfile.pdf', 'rb').read(), receiver.fingerprint, sender.fingerprint, 'sender_pwd', True)
        self.assertTrue(encrypted.data.startswith('-----BEGIN PGP MESSAGE-----'), 'Cannot encrypt/sign')


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.test_export_keys']
    unittest.main()
