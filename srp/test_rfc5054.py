#!/usr/bin/env python
#
# Cross-checks both pysrp backends against the SRP-6a test vectors from
# RFC 5054 Appendix B. The expected values are additionally recomputed
# here with an independent, minimal pure-Python implementation so the
# test does not simply trust the library's own derivations.

import unittest
import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import srp
import srp._pysrp as _pysrp

try:
    import srp._ctsrp as _ctsrp
except (ImportError, OSError):
    _ctsrp = None


# ---------------------------------------------------------------------------
# RFC 5054 Appendix B test vectors (N, g are the 1024-bit group of Appendix A)
# ---------------------------------------------------------------------------

RFC_I = b'alice'
RFC_P = b'password123'

RFC_s = 'BEB25379D1A8581EB5A727673A2441EE'
RFC_k = '7556AA045AEF2CDD07ABAF0F665C3E818913186F'
RFC_x = '94B7555AABE9127CC58CCF4993DB6CF84D16C124'
RFC_v = (
    '7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812'
    '9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5'
    'C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5'
    'EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78'
    'E955A5E29E7AB245DB2BE315E2099AFB')
RFC_a = '60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393'
RFC_b = 'E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20'
RFC_A = (
    '61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4'
    '4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC'
    '8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44'
    'BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA'
    'B349EF5D76988A3672FAC47B0769447B')
RFC_B = (
    'BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011'
    'BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99'
    '6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA'
    '37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE'
    'EB4012B7D7665238A8E3FB004B117B58')
RFC_u = 'CE38B9593487DA98554ED47D70A7AE5F462EF019'
RFC_S = (
    'B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D'
    '233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C'
    '41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F'
    '3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D'
    'C346D7E474B29EDE8A469FFECA686E5A')

# 1024-bit group from RFC 5054 Appendix A (== srp.NG_1024)
RFC_N = (
    'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C'
    '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4'
    '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29'
    '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A'
    'FD5138FE8376435B9FC61D2FC0EB06E3')
RFC_g = 2


def _i2b(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''


def _sha1(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update(p)
    return h.digest()


class _Independent:
    """
    Independent recomputation of every RFC 5054 Appendix B value using
    nothing but hashlib and modular exponentiation.
    """
    def __init__(self):
        N = int(RFC_N, 16)
        g = RFC_g
        nbytes = (N.bit_length() + 7) // 8
        pad = lambda n: n.to_bytes(nbytes, 'big')

        s = bytes.fromhex(RFC_s)
        x = int.from_bytes(_sha1(s, _sha1(RFC_I + b':' + RFC_P)), 'big')
        v = pow(g, x, N)
        k = int.from_bytes(_sha1(pad(N), pad(g)), 'big')
        a = int(RFC_a, 16)
        b = int(RFC_b, 16)
        A = pow(g, a, N)
        B = (k * v + pow(g, b, N)) % N
        u = int.from_bytes(_sha1(pad(A), pad(B)), 'big')
        S_client = pow(B - k * v, a + u * x, N)
        S_server = pow(A * pow(v, u, N), b, N)

        assert S_client == S_server

        hN_xor_hg = bytes(x_ ^ y_ for x_, y_ in zip(_sha1(pad(N)), _sha1(pad(g))))
        K = _sha1(_i2b(S_client))
        M1 = _sha1(hN_xor_hg, _sha1(RFC_I), s, _i2b(A), _i2b(B), K)
        M2 = _sha1(_i2b(A), M1, K)

        self.N, self.g, self.nbytes = N, g, nbytes
        self.s, self.x, self.v, self.k = s, x, v, k
        self.a, self.b, self.A, self.B = a, b, A, B
        self.u, self.S, self.K, self.M1, self.M2 = u, S_client, K, M1, M2


class RFC5054Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.exp = _Independent()

    def setUp(self):
        _pysrp.rfc5054_enable(True)
        if _ctsrp:
            _ctsrp.rfc5054_enable(True)

    def tearDown(self):
        _pysrp.rfc5054_enable(False)
        if _ctsrp:
            _ctsrp.rfc5054_enable(False)

    def test_independent_recomputation_matches_rfc(self):
        # Sanity check of the independent implementation itself against
        # the values published in RFC 5054 Appendix B.
        e = self.exp
        self.assertEqual(e.x, int(RFC_x, 16))
        self.assertEqual(e.v, int(RFC_v, 16))
        self.assertEqual(e.k, int(RFC_k, 16))
        self.assertEqual(e.A, int(RFC_A, 16))
        self.assertEqual(e.B, int(RFC_B, 16))
        self.assertEqual(e.u, int(RFC_u, 16))
        self.assertEqual(e.S, int(RFC_S, 16))

    def _run_handshake(self, mod, secret_len):
        e = self.exp

        usr = mod.User(RFC_I, RFC_P,
                       hash_alg=mod.SHA1, ng_type=mod.NG_1024,
                       bytes_a=_i2b(e.a).rjust(secret_len, b'\0'))
        uname, A_bytes = usr.start_authentication()
        self.assertEqual(uname, RFC_I)
        self.assertEqual(int.from_bytes(A_bytes, 'big'), e.A)

        svr = mod.Verifier(uname, e.s, _i2b(e.v), A_bytes,
                           hash_alg=mod.SHA1, ng_type=mod.NG_1024,
                           bytes_b=_i2b(e.b).rjust(secret_len, b'\0'))
        s_bytes, B_bytes = svr.get_challenge()
        self.assertEqual(s_bytes, e.s)
        self.assertEqual(int.from_bytes(B_bytes, 'big'), e.B)

        # k = SHA1(N | PAD(g))
        k_val = svr.k if isinstance(svr.k, int) else int.from_bytes(mod.bn_to_bytes(svr.k), 'big')
        self.assertEqual(k_val, e.k)

        M1 = usr.process_challenge(s_bytes, B_bytes)
        self.assertIsNotNone(M1)
        self.assertEqual(M1, e.M1)

        H_AMK = svr.verify_session(M1)
        self.assertIsNotNone(H_AMK)
        self.assertEqual(H_AMK, e.M2)

        usr.verify_session(H_AMK)
        self.assertTrue(usr.authenticated())
        self.assertTrue(svr.authenticated())

        # K = SHA1(S) on both sides
        self.assertEqual(usr.get_session_key(), e.K)
        self.assertEqual(svr.get_session_key(), e.K)

        # u and the premaster secret S where the backend exposes them
        usr_u = usr.u if isinstance(usr.u, int) else int.from_bytes(mod.bn_to_bytes(usr.u), 'big')
        usr_S = usr.S if isinstance(usr.S, int) else int.from_bytes(mod.bn_to_bytes(usr.S), 'big')
        svr_S = svr.S if isinstance(svr.S, int) else int.from_bytes(mod.bn_to_bytes(svr.S), 'big')
        self.assertEqual(usr_u, e.u)
        self.assertEqual(usr_S, e.S)
        self.assertEqual(svr_S, e.S)

    def test_rfc5054_vectors_pure_python(self):
        # _pysrp requires 256-byte ephemeral secrets; left-padding with
        # zeros preserves the integer value.
        self._run_handshake(_pysrp, 256)

    @unittest.skipIf(_ctsrp is None, 'ctypes/OpenSSL backend unavailable')
    def test_rfc5054_vectors_ctypes(self):
        # _ctsrp requires 32-byte ephemeral secrets.
        self._run_handshake(_ctsrp, 32)

    @unittest.skipIf(_ctsrp is None, 'ctypes/OpenSSL backend unavailable')
    def test_rfc5054_vectors_cross_backend(self):
        # Client on the pure-Python backend, server on the ctypes backend.
        e = self.exp
        usr = _pysrp.User(RFC_I, RFC_P, hash_alg=srp.SHA1, ng_type=srp.NG_1024,
                          bytes_a=_i2b(e.a).rjust(256, b'\0'))
        uname, A_bytes = usr.start_authentication()
        svr = _ctsrp.Verifier(uname, e.s, _i2b(e.v), A_bytes,
                              hash_alg=srp.SHA1, ng_type=srp.NG_1024,
                              bytes_b=_i2b(e.b))
        s_bytes, B_bytes = svr.get_challenge()
        M1 = usr.process_challenge(s_bytes, B_bytes)
        H_AMK = svr.verify_session(M1)
        usr.verify_session(H_AMK)
        self.assertEqual(M1, e.M1)
        self.assertEqual(H_AMK, e.M2)
        self.assertTrue(usr.authenticated())
        self.assertTrue(svr.authenticated())


if __name__ == '__main__':
    unittest.main(verbosity=2)
