#!/usr/bin/env python
#
# Tests for configurable SRP-6a group parameters, M1/M2 proof
# verification, and replay protection.

import unittest
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import srp
import srp._pysrp as _pysrp

try:
    import srp._ctsrp as _ctsrp
except (ImportError, OSError):
    _ctsrp = None

_mods = [m for m in (_pysrp, _ctsrp) if m is not None]

# 1024-bit group from RFC 5054 Appendix A, used as a custom group.
CUSTOM_N_HEX = (
    'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
    '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
    '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
    '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
    'FD5138FE8376435B9FC61D2FC0EB06E3')
CUSTOM_G_HEX = '2'

USERNAME = b'testuser'
PASSWORD = b'testpassword'


def run_handshake(test, mod, username=USERNAME, password=PASSWORD,
                  verifier_password=PASSWORD, replay_cache=None, **kw):
    _s, _v = mod.create_salted_verification_key(USERNAME, verifier_password, **kw)
    usr = mod.User(username, password, **kw)
    uname, A = usr.start_authentication()
    svr = mod.Verifier(uname, _s, _v, A, replay_cache=replay_cache, **kw)
    s, B = svr.get_challenge()
    M = usr.process_challenge(s, B)
    H_AMK = svr.verify_session(M) if M is not None else None
    if H_AMK is not None:
        usr.verify_session(H_AMK)
    return usr, svr, M, H_AMK


class CustomGroupTest(unittest.TestCase):

    def test_custom_group_handshake(self):
        for mod in _mods:
            usr, svr, M, H_AMK = run_handshake(
                self, mod, ng_type=mod.NG_CUSTOM,
                n_hex=CUSTOM_N_HEX, g_hex=CUSTOM_G_HEX)
            self.assertIsNotNone(M)
            self.assertIsNotNone(H_AMK)
            self.assertTrue(usr.authenticated())
            self.assertTrue(svr.authenticated())
            self.assertEqual(usr.get_session_key(), svr.get_session_key())

    def test_custom_group_requires_both_params(self):
        for mod in _mods:
            with self.assertRaises(ValueError):
                mod.User(USERNAME, PASSWORD, ng_type=mod.NG_CUSTOM,
                         n_hex=CUSTOM_N_HEX)
            with self.assertRaises(ValueError):
                mod.Verifier(USERNAME, b'salt', b'verifier',
                             ng_type=mod.NG_CUSTOM, g_hex=CUSTOM_G_HEX)
            with self.assertRaises(ValueError):
                mod.create_salted_verification_key(
                    USERNAME, PASSWORD, ng_type=mod.NG_CUSTOM)

    def test_invalid_group_params_rejected(self):
        N = int(CUSTOM_N_HEX, 16)
        bad = [
            (format(N - 1, 'x'), CUSTOM_G_HEX),  # even N
            ('ff', CUSTOM_G_HEX),                # N too small
            (CUSTOM_N_HEX, '1'),                 # g < 2
            (CUSTOM_N_HEX, format(N - 1, 'x')),  # g > N-2
        ]
        for mod in _mods:
            for n_hex, g_hex in bad:
                with self.assertRaises(ValueError):
                    mod.User(USERNAME, PASSWORD, ng_type=mod.NG_CUSTOM,
                             n_hex=n_hex, g_hex=g_hex)

    def test_validate_group_params_exported(self):
        N = int(CUSTOM_N_HEX, 16)
        srp.validate_group_params(N, 2)
        with self.assertRaises(ValueError):
            srp.validate_group_params(N - 1, 2)
        with self.assertRaises(ValueError):
            srp.validate_group_params(N, 1)


class ProofVerificationTest(unittest.TestCase):

    def test_wrong_password_fails_m1(self):
        for mod in _mods:
            usr, svr, M, H_AMK = run_handshake(
                self, mod, password=b'wrongpassword')
            self.assertIsNotNone(M)
            self.assertIsNone(H_AMK)
            self.assertFalse(svr.authenticated())
            self.assertFalse(usr.authenticated())
            self.assertIsNone(svr.get_session_key())

    def test_tampered_m1_rejected(self):
        for mod in _mods:
            _s, _v = mod.create_salted_verification_key(USERNAME, PASSWORD)
            usr = mod.User(USERNAME, PASSWORD)
            uname, A = usr.start_authentication()
            svr = mod.Verifier(uname, _s, _v, A)
            s, B = svr.get_challenge()
            M = bytearray(usr.process_challenge(s, B))
            M[0] ^= 0x01
            self.assertIsNone(svr.verify_session(bytes(M)))
            self.assertFalse(svr.authenticated())

    def test_tampered_m2_rejected(self):
        for mod in _mods:
            usr, svr, M, H_AMK = run_handshake(self, mod)
            self.assertTrue(svr.authenticated())
            bad = bytearray(H_AMK)
            bad[0] ^= 0x01
            usr2 = mod.User(USERNAME, PASSWORD)
            usr2.verify_session(bytes(bad))
            self.assertFalse(usr2.authenticated())

    def test_user_not_authenticated_without_challenge(self):
        # Regression: verify_session(None) must not authenticate a User
        # that never processed a challenge.
        for mod in _mods:
            usr = mod.User(USERNAME, PASSWORD)
            usr.verify_session(None)
            self.assertFalse(usr.authenticated())
            self.assertIsNone(usr.get_session_key())


class ReplayProtectionTest(unittest.TestCase):

    def test_verifier_is_single_use(self):
        for mod in _mods:
            _s, _v = mod.create_salted_verification_key(USERNAME, PASSWORD)
            usr = mod.User(USERNAME, PASSWORD)
            uname, A = usr.start_authentication()
            svr = mod.Verifier(uname, _s, _v, A)
            s, B = svr.get_challenge()
            M = usr.process_challenge(s, B)
            self.assertIsNotNone(svr.verify_session(M))
            self.assertTrue(svr.authenticated())
            # Replaying the same proof against the same Verifier fails.
            self.assertIsNone(svr.verify_session(M))

    def test_replay_cache_rejects_reused_proof(self):
        for mod in _mods:
            cache = mod.ReplayCache()
            _s, _v = mod.create_salted_verification_key(USERNAME, PASSWORD)

            usr = mod.User(USERNAME, PASSWORD)
            uname, A = usr.start_authentication()
            svr1 = mod.Verifier(uname, _s, _v, A, replay_cache=cache)
            s, B = svr1.get_challenge()
            M = usr.process_challenge(s, B)
            self.assertIsNotNone(svr1.verify_session(M))

            # A fresh Verifier (e.g. after a server restart within the
            # cache lifetime) must reject the replayed proof.
            svr2 = mod.Verifier(uname, _s, _v, A, replay_cache=cache)
            self.assertIsNone(svr2.verify_session(M))
            self.assertFalse(svr2.authenticated())

    def test_replay_cache_accepts_fresh_proof(self):
        for mod in _mods:
            cache = mod.ReplayCache()
            usr, svr, M, H_AMK = run_handshake(self, mod, replay_cache=cache)
            self.assertTrue(usr.authenticated())
            self.assertTrue(svr.authenticated())

    def test_replay_cache_set_like(self):
        # Plain sets are accepted as a minimal replay cache.
        for mod in _mods:
            cache = set()
            _s, _v = mod.create_salted_verification_key(USERNAME, PASSWORD)
            usr = mod.User(USERNAME, PASSWORD)
            uname, A = usr.start_authentication()
            svr1 = mod.Verifier(uname, _s, _v, A, replay_cache=cache)
            s, B = svr1.get_challenge()
            M = usr.process_challenge(s, B)
            self.assertIsNotNone(svr1.verify_session(M))
            svr2 = mod.Verifier(uname, _s, _v, A, replay_cache=cache)
            self.assertIsNone(svr2.verify_session(M))

    def test_replay_cache_expiry(self):
        cache = _pysrp.ReplayCache(ttl_seconds=0.2)
        self.assertTrue(cache.check_and_add(b'proof'))
        self.assertFalse(cache.check_and_add(b'proof'))
        time.sleep(0.3)
        self.assertTrue(cache.check_and_add(b'proof'))

    def test_replay_cache_exported(self):
        self.assertIsNotNone(srp.ReplayCache)


if __name__ == '__main__':
    unittest.main(verbosity=2)
