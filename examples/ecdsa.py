"""
ECDSA signature scheme.

Requires Python >= 2.6.
"""
import hashlib
import random
import wcurve

def _big_int_unpack_be(seq):
    p = None
    if isinstance(seq, str):
        p = lambda x: ord(x)
    else:
        p = lambda x: x
    return sum([p(seq[i]) << (i * 8) for i in range(len(seq) - 1, -1, -1)])

def generate_keypair(curve):
    sk = random.SystemRandom().randint(1, curve.n - 1)
    pk = sk * curve.base_point
    pk.canonicalize()
    return sk, pk

def sign(secret_key, msg):
    curve = wcurve.secp256r1_curve()
    while True:
        k, epk = generate_keypair(curve)
        r = epk.x % curve.n
        if r == 0:
            continue
        e = _big_int_unpack_be(hashlib.sha256(msg).digest())
        kinv = wcurve._FpArithmetic(curve.n).inverse(k)
        s = (kinv * (e + r * secret_key)) % curve.n
        if s == 0:
            continue
        return r, s

def verify(public_key, signature, msg):
    r, s = signature
    curve = wcurve.secp256r1_curve()
    for v in signature:
        if not (1 <= v <= (curve.n - 1)):
            return False
    e = _big_int_unpack_be(hashlib.sha256(msg).digest())
    sinv = wcurve._FpArithmetic(curve.n).inverse(s)
    u1 = e * sinv % curve.n
    u2 = r * sinv % curve.n
    q = u1 * curve.base_point + u2 * public_key
    if q.is_at_infinity():
        return False
    v = q.get_affine_x() % curve.n
    if r == v:
        return True
    return False

if __name__ == '__main__':
    curve = wcurve.secp256r1_curve()
    sk, pk = generate_keypair(curve)
    msg = b"My message to sign"
    sig = sign(sk, msg)
    print('Valid signature: %s' % verify(pk, sig, msg))
