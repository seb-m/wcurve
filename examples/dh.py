"""
DH
"""
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

def generate_secretkey(curve):
    return random.SystemRandom().randint(1, curve.n - 1)

def compute_pubkey(curve, secret_key):
    return secret_key * curve.base_point

def compute_sharedkey(secret_key, pub_key):
    if not pub_key.is_valid():
        return
    return secret_key * pub_key

def run(curve, tag):
    sk1 = generate_secretkey(curve)
    sk2 = generate_secretkey(curve)

    pk1 = compute_pubkey(curve, sk1)
    start = time.time()
    pk2 = compute_pubkey(curve, sk2)
    pub_time = time.time() - start

    sh1 = compute_sharedkey(sk1, pk2)
    assert sh1 is not None
    start = time.time()
    sh2 = compute_sharedkey(sk2, pk1)
    shared_time = time.time() - start
    assert sh2 is not None

    print('%-25s: pub_key=%0.3fs  shared_key=%0.3fs  equals=%s' % \
              (tag, pub_time, shared_time, sh1 == sh2))

if __name__ == '__main__':
    run(wcurve.secp256r1_curve(), 'secp256r1')
    run(wcurve.secp256r1_curve_infective(),
        'secp256r1_curve_infective')
