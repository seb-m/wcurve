"""
ECDSA signature scheme.

Requires Python >= 2.4 (http://pypi.python.org/pypi/hashlib is needed for
python2.4).
"""
import hashlib
import random
import time
# Local import
try:
    import wcurve
except:  # lazy trick for py3k
    from os.path import abspath, dirname
    import sys
    parent = dirname(dirname(abspath(__file__)))
    sys.path.append(parent)
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
    pk.canonicalize()  # needed for ephemeral key gen in sign()
    return sk, pk

def sign(curve, secret_key, msg):
    assert isinstance(curve, wcurve._Curve)
    while True:
        esk, epk = generate_keypair(curve)
        r = epk.x % curve.n
        if r == 0:
            continue
        e = _big_int_unpack_be(hashlib.sha256(msg.encode('utf8')).digest())
        kinv = wcurve._FpArithmetic(curve.n).inverse(esk)
        s = (kinv * (e + r * secret_key)) % curve.n
        if s == 0:
            continue
        return r, s

def verify(pub_key, signature, msg):
    if not isinstance(pub_key, wcurve.JacobianPoint):
        return False
    r, s = signature
    curve = pub_key.curve
    for v in signature:
        if not (1 <= v <= (curve.n - 1)):
            return False
    e = _big_int_unpack_be(hashlib.sha256(msg.encode('utf8')).digest())
    sinv = wcurve._FpArithmetic(curve.n).inverse(s)
    u1 = e * sinv % curve.n
    u2 = r * sinv % curve.n
    q = u1 * curve.base_point + u2 * pub_key
    if q.is_at_infinity():
        return False
    v = q.get_affine_x() % curve.n
    if r == v:
        return True
    return False

def run(curve, tag):
    sk, pk = generate_keypair(curve)
    msg = "My message to sign"

    # Signature
    start = time.time()
    sig = sign(curve, sk, msg)
    sign_time = time.time() - start

    # For signature verification there is no meaning of using infective
    # computations in scalar multiplications.
    if curve.infective:
        pk.curve = wcurve.secp256r1_curve()

    # Verification
    start = time.time()
    # /!\ in a real implementation the public key would most likely come
    # from an untrusted remote party so it would then be required to check
    # the validity of the public key before calling this function. That is
    # instantiating the right curve, calling JacobianPoint.from_affine()
    # or JacobianPoint.uncompress(), and calling JacobianPoint.is_valid().
    valid = verify(pk, sig, msg)
    verify_time = time.time() - start

    print('%-25s: sign=%0.3fs  verify=%0.3fs  valid=%s' % \
              (tag, sign_time, verify_time, valid))

if __name__ == '__main__':
    run(wcurve.secp256r1_curve(), 'secp256r1')
    run(wcurve.secp256r1_curve_infective(),
        'secp256r1_curve_infective')
