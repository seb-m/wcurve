"""
Author: Sebastien Martini (seb@dbzteam.org)
License: MIT
"""
import unittest
import binascii
import copy
import math
import os
import random
import subprocess
import sys
# Local imports
import wcurve

if sys.version_info < (3, 0):
    def _big_int_unpack_be(seq):
        return sum([ord(b) << ((len(seq) - 1 - i) << 3) for i, b in enumerate(seq)])

    def _big_int_pack_be(n):
        nl = int(math.ceil(float(wcurve._bit_length(n)) / 8))
        return ''.join([chr((n >> (i * 8)) & 0xff) for i in range(nl - 1,
                                                                  -1, -1)])
    def _be_unhex(s):
        return _big_int_unpack_be(binascii.unhexlify('0' * (len(s) % 2) + s))

else:
    def _big_int_unpack_be(byte_seq):
        r = 0
        i = len(byte_seq) - 1
        for c in byte_seq:
            r += c << (i * 8)
            i -= 1
        return r

    def _big_int_pack_be(n):
        nl = math.ceil(n.bit_length() / 8)
        return bytes((n >> (i * 8)) & 0xff for i in range(nl - 1, -1, -1))

    def _be_unhex(s):
        if isinstance(s, bytes):
            s = s.decode('ascii')
        s = '0' * (len(s) % 2) + s
        return _big_int_unpack_be(bytes.fromhex(s))

def _be_hex(n):
    return binascii.hexlify(_big_int_pack_be(n))

def _rand_point(curve):
    while True:
        x = random.SystemRandom().randint(1, curve.p - 1)
        pt = wcurve.JacobianPoint.uncompress(x, 0, curve)
        if pt.is_on_curve():
            return pt

def _compile_ref(bin_path):
    if os.path.exists(bin_path) or not os.path.exists(bin_path + '.c'):
        return False
    os.system('gcc -W -Wall -o %s %s.c -lcrypto' % (bin_path, bin_path))
    return True

def _run_cmd(cmd):
    r = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    stdout, _ = r.communicate()
    if r.returncode != 0:
        return None
    return stdout


class TestWCurveArithmetic(unittest.TestCase):
    def setUp(self):
        self.cwd = os.path.dirname(os.path.abspath(__file__))
        self.curve_name = 'prime256v1'
        self.curve = wcurve.secp256r1_curve()
        self.curve_infective = wcurve.secp256r1_curve_infective()
        self.bin = 'ec_ref'
        self.bin_path = os.path.join(self.cwd, self.bin)

    def testEq(self):
        self.assertEqual(self.curve.base_point, self.curve.base_point)
        self.assertEqual(self.curve.point_at_infinity, self.curve.point_at_infinity)
        self.assertEqual(self.curve.point_at_infinity, -self.curve.point_at_infinity)
        self.assertFalse(self.curve.base_point == self.curve.point_at_infinity)
        self.assertTrue(self.curve.base_point != self.curve.point_at_infinity)
        curve2 = wcurve.secp256r1_curve()
        self.assertEqual(self.curve, self.curve)
        self.assertEqual(self.curve, curve2)
        self.assertEqual(self.curve.base_point, curve2.base_point)
        curve2.n = 42
        self.assertNotEqual(self.curve, curve2)
        self.assertNotEqual(self.curve.base_point, curve2.base_point)

    def testSub(self):
        r = self.curve.base_point - self.curve.base_point
        self.assertEqual(r, self.curve.point_at_infinity)
        r = self.curve.point_at_infinity - self.curve.point_at_infinity
        self.assertEqual(r, self.curve.point_at_infinity)
        r = self.curve.base_point - self.curve.point_at_infinity
        self.assertEqual(r, self.curve.base_point)
        r = self.curve.point_at_infinity - self.curve.base_point
        self.assertEqual(r, -self.curve.base_point)

    def testNeg(self):
        r = -self.curve.base_point
        bp = copy.copy(self.curve.base_point)
        bp.y = -bp.y % self.curve.p
        self.assertEqual(r, bp)
        self.assertEqual(-r, self.curve.base_point)
        r = -self.curve.point_at_infinity
        self.assertEqual(r, self.curve.point_at_infinity)

    def testAdd(self):
        r = self.curve.base_point + self.curve.point_at_infinity
        self.assertEqual(r, self.curve.base_point)
        r = self.curve.base_point + (2 * self.curve.base_point)
        self.assertEqual(r, (3 * self.curve.base_point))
        r = self.curve.base_point + self.curve.base_point
        self.assertEqual(r, 2 * self.curve.base_point)
        r = self.curve.point_at_infinity + self.curve.point_at_infinity
        self.assertEqual(r, self.curve.point_at_infinity)
        s1 = random.SystemRandom().randint(1, self.curve.n - 1)
        s2 = random.SystemRandom().randint(1, self.curve.n - 1)
        r = s1 * self.curve.base_point + s2 * self.curve.base_point
        self.assertEqual(r, (s1 + s2) * self.curve.base_point)

    def testScalarMul(self):
        r = self.curve.n * self.curve.base_point
        self.assertEqual(r, self.curve.point_at_infinity)
        r = 1 * self.curve.base_point
        self.assertEqual(r, self.curve.base_point)
        s = random.SystemRandom().randint(1, self.curve.n - 1)
        r = s * self.curve.base_point
        r = r.to_affine()
        r = wcurve.JacobianPoint(r[0], r[1], 1, self.curve)
        r = self.curve.n * r
        self.assertEqual(r, self.curve.point_at_infinity)
        self.assertRaises(ValueError,
                          lambda: 2 * self.curve.point_at_infinity)
        b = copy.copy(self.curve.base_point)
        b.x += 1
        self.assertRaises(ValueError, lambda: 2 * b)
        r = 0 * self.curve.base_point
        self.assertEqual(r, self.curve.point_at_infinity)
        r1 = (-42) * self.curve.base_point
        r2 = ((-42) % self.curve.n) * self.curve.base_point
        self.assertEqual(r1, r2)

    def testScalarMulRef(self):
        # (x, y) = s * base_point obtained with openssl
        s = 55410786546881778422887285187544511127100960212956419513245461364050667784185
        x = 64169503900361343289983195807258161414745802527383776807124463141740561324790
        y = 111970075840193383282111507227885172446728586957098158699813435561710172438460
        ref = wcurve.JacobianPoint(x, y, 1, self.curve)
        r = s * self.curve.base_point
        self.assertEqual(r, ref)

    def testCompression(self):
        bit_y = self.curve.base_point.compression_bit_y()
        p = wcurve.JacobianPoint.uncompress(self.curve.base_point.x, bit_y, self.curve)
        self.assertEqual(p, self.curve.base_point)
        p = wcurve.JacobianPoint.uncompress(self.curve.base_point.x, 1 - bit_y, self.curve)
        self.assertEqual(p, -self.curve.base_point)

    def testScalarMulAgainstRef(self):
        cmd = [self.bin_path, self.curve_name]
        self.assertTrue(_compile_ref(self.bin_path))
        try:
            for i in range(10):
                sa = random.SystemRandom().randint(1, self.curve.n - 1)
                sb = random.SystemRandom().randint(1, self.curve.n - 1)

                a = _rand_point(self.curve)
                b = _rand_point(self.curve)
                ax, ay = a.to_affine()
                bx, by = b.to_affine()

                stdout = _run_cmd(cmd + [_be_hex(sa), _be_hex(ax),
                                         _be_hex(ay),
                                         _be_hex(sb), _be_hex(bx),
                                         _be_hex(by)])
                self.assertTrue(stdout)
                lines = stdout.splitlines()
                self.assertEqual(len(lines), 2)

                r = wcurve.JacobianPoint.from_affine(_be_unhex(lines[0]),
                                                     _be_unhex(lines[1]),
                                                     self.curve)
                rr = sa * a + sb * b
                self.assertEqual(r, rr)
        finally:
            os.unlink(self.bin_path)

    def testScalarMulInfective(self):
        sk = random.SystemRandom().randint(1, self.curve.n - 1)
        pk1 = sk * self.curve.base_point
        pk2 = sk * self.curve_infective.base_point
        self.assertEqual(pk1, pk2)

    def testScalarMulInfectiveAgainstRef(self):
        curve = self.curve
        self.curve = self.curve_infective
        try:
            self.testScalarMulAgainstRef()
        finally:
            self.curve = curve


if __name__ == '__main__':
    unittest.main()
