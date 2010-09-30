"""
This package implements basic arithmetic operations such as point addition and
single-scalar multiplication on elliptic curves in short Weiertsrass form.

Example:
    import wcurve, random
    # Instantiate secp256r1 standardized curve
    curve  = wcurve.secp256r1_curve()
    # Generate a new secret value
    sk = random.SystemRandom().randint(1, curve.n - 1)
    # Compute the public key associated to the previous secret
    pk = sk * curve.base_point
    # Get its affine coordinates
    pkx, pky = pk.to_affine()

Internally curve points are represented in Jacobian coordinates. There's
currently no optimized implementation for the double scalar multiplication
operation, it is merely the addition of two independents single-scalar
multiplications.

The primary goal of this code is to keep things simple and offer a pure
Python standalone interface to some of the currently most used curves.

As implemented, single-scalar multiplications are not protected against DPA and
some types of fault attacks. However, exponentiations algorithms are regulars,
without dummy operation and conditional branching instructions are avoided.

Beside to the usual scalar multiplication algorithm (transparently used with
secp256r1_curve()) another algorithm is implemented. This one additionally
checks the correctness of its result before returning it. It is automatically
used when a secp256r1_curve_with_correctness_check() curve is instantiated. Also
see scalar_multiplication_infective() for more details.

Dependancies: Python >= 2.4
Author: Sebastien Martini (seb@dbzteam.org)
License: MIT
"""
import copy
import random

__author__ = "Sebastien Martini (seb@dbzteam.org)"

__version__ = "0.0.6"

# Functions, classes, methods prefixed with '_' are privates and are not
# intended to be called directly.

def _check_integer_type(val):
    """
    Check val is an integer.
    """
    try:
        import numbers
        if isinstance(val, numbers.Integral):
            return
    except:
        if isinstance(val, int) or isinstance(val, long):
            return
    raise TypeError("Invalid type %s, expected integral type." % type(val))

def _bit_length(x):
    """
    Returns |x|.
    """
    x = abs(x)
    # Try to use r to protect the top bit of x.
    r = random.SystemRandom().randint(0, 64)
    x = x << r
    # See comment in JacobianPoint.scalar_multiplication().
    if not x:
        return 0
    n = -r
    while x:
        n += 1
        x >>= 1
    return n

def _cond_swap_values(swap, u, v):
    """
    Conditionally swap u and v if swap=1 and otherwise left unchanged if
    swap=0. The value of swap must be 0 or 1 exclusively.
    """
    swap_diff = (-swap) & (u ^ v)
    return u ^ swap_diff, v ^ swap_diff


class _FpArithmetic:
    def __init__(self, p):
        """
        You shouldn't have to instantiate this class directly.
        p must be a prime.
        """
        self.p = p

    def exp(self, g, k, k_num_bits):
        return self._exp(g, k, k_num_bits, self.p)

    def _exp(self, g, k, k_num_bits, n):
        """
        Montgomery Ladder. Compute g^k mod n with |k| = k_num_bits.
        """
        r0 = 1
        r1 = g
        while k_num_bits >= 0:
            cur_bit = (k >> k_num_bits) & 1
            r0, r1 = _cond_swap_values(1 - cur_bit, r0, r1)
            r0 = r0 * r1 % n
            r1 = r1 ** 2 % n
            r0, r1 = _cond_swap_values(1 - cur_bit, r0, r1)
            k_num_bits -= 1
        return r0

    def inverse(self, g):
        """
        Returns inverse of g mod p.
        """
        return self._inverse(g, self.p)

    def _inverse(self, g, n):
        """
        Returns inverse of g mod n.
        """
        if g % n == 0:
            raise ValueError("%d has no inverse mod %d." % (g, n))
        return self._exp(g, n - 2, _bit_length(n - 2), n)

    def crt(self, l, modulus):
        """
        Compute a list of crts sharing the same modulus.
        """
        prod = 1
        for m in modulus:
            prod *= m
        ldiv = tuple(map(lambda m: prod // m, modulus))
        linv = tuple(map(self._inverse, ldiv, modulus))
        def _sum(a):
            t = sum(map(lambda x, y, z: x * y * z, a, linv, ldiv))
            return t % prod
        return tuple(map(_sum, l))


class _CoZArithmetic:
    """
    Co-Z arithmetic from "Co-Z Addition Formulae and Binary Ladders on Elliptic
    Curves", Raveen R. Goundar and Marc Joye and Atsuko Miyaji. The zaddu, zaddc
    and dblu formulas are copied from the Appendix A and the section 4.3 of this
    paper.
    """
    def __init__(self, curve):
        """
        You shouldn't have to instantiate this class directly.
        """
        self.curve = curve

    def zaddu(self, p, q):
        """
        Point addition with update.

        (R,P)=ZADDU(P,Q) where R=P+Q=(X3:Y3:Z3) and P=(h2X1:h3Y1:Z3)
        with Z3=hZ1 for some h!=0
        """
        assert p.z % self.curve.p == q.z % self.curve.p
        t1 = p.x; t2 = p.y; t3 = p.z; t4 = q.x; t5 = q.y;
        t6 = t1 - t4
        t3 = t3 * t6 % self.curve.p  # z3
        t6 = t6 ** 2 % self.curve.p  # c
        t1 = t1 * t6 % self.curve.p  # w1
        t6 = t6 * t4 % self.curve.p  # w2
        t5 = t2 - t5
        t4 = t5 ** 2 % self.curve.p  # d
        t4 = t4 - t1
        t4 = (t4 - t6) % self.curve.p  # x3
        t6 = t1 - t6
        t2 = t2 * t6 % self.curve.p  # a1
        t6 = t1 - t4
        t5 = t5 * t6 % self.curve.p
        t5 = (t5 - t2) % self.curve.p  # y3
        return (JacobianPoint(t4, t5, t3, self.curve),
                JacobianPoint(t1, t2, t3, self.curve))

    def zaddc(self, p, q):
        """
        Conjugate point addition.

        (R,S)=ZADDC(P,Q) where R=P+Q=(X3:Y3:Z3) and S=P-Q=(X3:Y3:Z3)
        """
        assert p.z % self.curve.p == q.z % self.curve.p
        t1 = p.x; t2 = p.y; t3 = p.z; t4 = q.x; t5 = q.y;
        t6 = t1 - t4
        t3 = t3 * t6 % self.curve.p
        t6 = t6 ** 2 % self.curve.p
        t7 = t1 * t6 % self.curve.p
        t6 = t6 * t4 % self.curve.p
        t1 = t2 + t5
        t4 = t1 ** 2 % self.curve.p
        t4 = t4 - t7
        t4 = (t4 - t6) % self.curve.p
        t1 = t2 - t5
        t1 = t1 ** 2 % self.curve.p
        t1 = t1 - t7
        t1 = (t1 - t6) % self.curve.p
        t6 = t6 - t7
        t6 = t6 * t2 % self.curve.p
        t2 = t2 - t5
        t5 = 2 * t5
        t5 = t2 + t5
        t7 = t7 - t4
        t5 = t5 * t7 % self.curve.p
        t5 = (t5 + t6) % self.curve.p
        t7 = t4 + t7
        t7 = t7 - t1
        t2 = t2 * t7 % self.curve.p
        t2 = (t2 + t6) % self.curve.p
        return (JacobianPoint(t1, t2, t3, self.curve),
                JacobianPoint(t4, t5, t3, self.curve))

    def dblu(self, p):
        """
        Initial point doubling (requires z=1).

        (2P,P) = DBLU(P)
        """
        assert p.z % self.curve.p == 1
        t1 = p.x; t2 = p.y; t3 = p.z;
        t4 = t1 ** 2 % self.curve.p  # b
        t5 = 3 * t4
        t5 = t5 + self.curve.a  # m
        t6 = t2 ** 2 % self.curve.p  # e
        t7 = t6 ** 2 % self.curve.p  # l
        t8 = t1 + t6
        t8 = t8 ** 2 % self.curve.p
        t8 = t8 - t4
        t8 = t8 - t7
        t8 = 2 * t8  # s
        t9 = t5 ** 2 % self.curve.p
        t9 = (t9 - 2 * t8) % self.curve.p  # x(2p)
        t10 = t8 - t9
        t10 = t5 * t10 % self.curve.p
        t11 = 8 * t7  # 8l
        t10 = (t10 - t11) % self.curve.p  # y(2p)
        t12 = 2 * t2 % self.curve.p  # z(2p)
        t1 = 4 * t1
        t1 = t1 * t6 % self.curve.p
        t2 = 8 * t7 % self.curve.p
        return (JacobianPoint(t9, t10, t12, self.curve),
                JacobianPoint(t1, t2, t12, self.curve))

    def scalar_multiplication(self, k, k_num_bits, p):
        """
        Montgomery ladder. Compute k * p.
        This algorithm does not work for k=0.
        """
        r0 = p
        r1, r0 = self.dblu(r0)
        for pos in range(k_num_bits - 2, -1, -1):
            cur_bit = (k >> pos) & 1
            r1._swap_coordinates(1 - cur_bit, r0)
            r0, r1 = self.zaddc(r1, r0)
            r1, r0 = self.zaddu(r0, r1)
            r1._swap_coordinates(1 - cur_bit, r0)
        return r0


class JacobianPoint:
    """
    Point representation in Jacobian coordinates.
    """
    def __init__(self, x, y, z, curve):
        """
        x, y, z are the Jacobian coordinates of this point, curve is the
        underlying/associated curve. curve must be a valid curve, it is the
        responsability of the caller to employ a valid and secure curve. curve
        is likely an instance of _Curve.
        """
        _check_integer_type(x)
        _check_integer_type(y)
        _check_integer_type(z)
        self.x = x
        self.y = y
        self.z = z
        self.curve = curve
        self.cozarithmetic = _CoZArithmetic(self.curve)
        self.fparithmetic = _FpArithmetic(self.curve.p)

    def _swap_coordinates(self, swap, point):
        """
        Conditionally swap the current coordinates values with those of 'point'.
        Coordinates are swapped if swap=1 and are left unchanged if swap=0. This
        value must be 1 or 0 exclusively.
        """
        for coord in ('x', 'y', 'z'):
            t0 = getattr(self, coord)
            t1 = getattr(point, coord)
            t0, t1 = _cond_swap_values(swap, t0, t1)
            setattr(self, coord, t0)
            setattr(point, coord, t1)

    def _to_equivalent(self, lmbda):
        """
        Compute (lmbda^2.x, lmbda^3.y, lmbda.z) in-place.
        """
        _check_integer_type(lmbda)
        if lmbda % self.curve.p == 0:
            return
        t1 = lmbda ** 2 % self.curve.p
        self.x = self.x * t1 % self.curve.p
        t1 = t1 * lmbda % self.curve.p
        self.y = self.y * t1 % self.curve.p
        self.z = self.z * lmbda % self.curve.p

    def normalize(self):
        """
        Transform this point to an equivalent representative having 1 for z
        coordinate (x : y : 1) when point is not at infinity and having x and y
        to 1 (1 : 1 : 0) when point is at infinity. This method is used for
        faciliting points comparisons and to convert a point to its affine
        representation. Before any transformation this method checks that the
        point is on curve.
        """
        # The point must be a valid point on curve. Otherwise it would
        # modify this point to a non-equivalent representation.
        assert self.is_on_curve()
        # Already normalized.
        if self.z % self.curve.p == 1:
            return
        # Point at infinity.
        if self.is_at_infinity():
            self.x = self.y = 1
            self.z = 0
        else:
            # k is public so there is no worry about using bit_length() here.
            t1 = self.fparithmetic.exp(self.z, 3, _bit_length(3))
            t1 = self.fparithmetic.inverse(t1)
            self.y = t1 * self.y % self.curve.p
            t1 = t1 * self.z
            self.x = t1 * self.x % self.curve.p
            self.z = 1

    def to_affine(self):
        """
        Convert this point to its affine representation (x/z**2, y/z**3).
        Does not work for point at infinity.
        """
        assert not self.is_at_infinity()
        self.normalize()
        return self.x, self.y

    def get_affine_x(self):
        return self.to_affine[0]

    def get_affine_y(self):
        return self.to_affine[1]

    def compression_bit_y(self):
        """
        Return the compression bit odd(y) associated to the y coordinate.
        Does not work for point at infinity.
        """
        assert not self.is_at_infinity()
        self.normalize()
        return self.y & 1

    @staticmethod
    def uncompress(x, bit_y, curve):
        """
        Uncompress and return the point represented by x and bit_y. See method
        compression_bit_y().
        """
        assert bit_y in (0, 1)
        assert curve.p % 4 == 3  # Required by the square root formulae.
        # y**2 = x**3 + ax + b
        t = x ** 3 % curve.p
        y2 = (t + curve.a * x + curve.b)  % curve.p
        # y = +/- y2 ** ((p + 1) / 4)
        e = (curve.p + 1) // 4
        y = _FpArithmetic(curve.p).exp(y2, e, _bit_length(e))
        if (y & 1) != bit_y:
            assert y != 0
            y = -y % curve.p
        assert (y & 1) == bit_y
        return JacobianPoint(x, y, 1, curve)

    def is_at_infinity(self):
        """
        This method is part of the validation done by is_valid().
        """
        if self.z % self.curve.p == 0:
            return True
        return False

    def has_valid_order(self):
        """
        Check the order of this point is the same than the order of the base
        point. This method is part of the validation done by is_valid().
        """
        if self.is_at_infinity():
            return False
        # Skip scalar mult if cofactor h=1
        if self.curve.h == 1:
            return True
        p = self._scalar_multiplication(self.curve.n, _bit_length(self.curve.n))
        return p.is_at_infinity()

    def is_on_curve(self):
        """
        Returns True if this point is on curve. This method is part of the
        validation done by is_valid().
        """
        t1 = self.y ** 2 % self.curve.p
        t2 = self.x ** 3 % self.curve.p
        t3 = self.z ** 3 % self.curve.p
        t4 = self.curve.a * self.x
        t4 = t4 * t3 * self.z % self.curve.p
        t2 = t2 + t4
        t3 = t3 ** 2 % self.curve.p
        t3 = self.curve.b * t3
        t2 = (t2 + t3) % self.curve.p
        return t1 == t2

    def is_valid(self):
        """
        Returns True if this point is valid.

        Check:
        1- P != O
        2- P is on curve
        3- n * P = O
        """
        if self.is_at_infinity():
            return False
        if not self.is_on_curve():
            return False
        if not self.has_valid_order():
            return False
        return True

    def __add__(self, point):
        """
        Adds two points.

        Very inefficient algorithm when used for double scalar multiplication,
        the only upside in this case is that it is formed of regular operations.
        Additions with identity points are handled as special cases.

        Usually points are publics elements (at least in the algorithms I know)
        therefore we're being slightly less careful in manipulating and
        comparing them.
        """
        if not isinstance(point, JacobianPoint):
            raise TypeError("Invalid type %s, expected type %s." % \
                                (type(point), JacobianPoint))

        if self.is_at_infinity():
            return copy.copy(point)
        elif point.is_at_infinity():
            return copy.copy(self)

        if self == point:
            # The formulaes forbid adding together two identical points, but we
            # can double one of them.
            return 2 * self

        # The two points must share the same z coordinates, it should be
        # more efficient to call _to_equivalent() than to_affine() which would
        # use a costly modular exponentiation with a big exponent.
        tmpz = self.z
        self._to_equivalent(point.z)
        point._to_equivalent(tmpz)
        r, _ = self.cozarithmetic.zaddu(self, point)
        return r

    def __sub__(self, point):
        point = -point
        return self + point

    def _scalar_multiplication(self, scalar, scalar_num_bits):
        """
        Do not call this method directly unless you know what you're doing.
        Instead use __mul__ and __rmul__ methods.
        """
        self.normalize()
        return self.cozarithmetic.scalar_multiplication(scalar,
                                                        scalar_num_bits,
                                                        self)

    def scalar_multiplication(self, scalar):
        """
        This method does the scalar multiplication of the submitted scalar with
        the current point. The scalar value is used as is, it is not randomized,
        it is not reduced mod n. Before the computation this point the final
        result are validated before being returned. If one validation step fails
        it raises a ValueError exception and immediately returns. See is_valid()
        to learn how the input point is validated. The result is only guaranteed
        to be a point on the curve, which doesn't ensure its correctness.

        There is nothing that prevent the use of first twos Coron's
        countermeasures priorly to the call of this method.

        Restrictions: scalar * infinity is not permitted.
        """
        _check_integer_type(scalar)
        if not self.is_valid():
            raise ValueError("Invalid input point.")
        # Test only for 0, not its congruents, because it only can't work for 0,
        # see _CoZArithmetic.scalar_multiplication for the reason.
        # 'not scalar' when scalar is a non-null long value calls long_nonzero()
        # from longobject.c. This method uses Py_SIZE() to return in O(1) the
        # previously known size of the long object. Eventually this value is
        # compared to 0, thus it won't compare or iterate the scalar value
        # directly.
        if not scalar:
            # This recopy is likely superfluous.
            return copy.copy(self.curve.point_at_infinity)

        # When a large scalar is compared to 0, long_compare() is called and
        # this branch is taken:
        # if (Py_SIZE(a) != Py_SIZE(b)) {
        #    sign = Py_SIZE(a) - Py_SIZE(b);
        # }
        # When scalar is negated it is recopied and its size value is negated.
        if scalar < 0:
            return (-scalar) * (-self)

        # Fixme: I would prefer not having to call _bit_length() at all, but it
        # would require to use a right-to-left exponentiation algorithm which in
        # this case has some constraints I'd prefer to avoid too.
        result_point = self._scalar_multiplication(scalar, _bit_length(scalar))
        if not result_point.is_on_curve():
            raise ValueError("Invalid result point.")
        return result_point

    def scalar_multiplication_infective(self, scalar):
        """
        This scalar multiplication checks the correctness of the final result
        but in a way where a non-exploitable wrong result is returned if an
        error is introduced in any part of the computation.

        This implementation follows the Algorithm 8 presented at section 4 of
        "Sign Change Fault Attacks On Elliptic Curve Cryptosystems" by Blomer,
        Otto and Seifert. It also uses 'infective computations' as suggested
        by the modified algorithm at the end of section 4.1.

        See function secp256r1_curve_with_correctness_check() for more details
        and an example. Also read the docstring of scalar_multiplication() it
        mostly applies to this method as well.
        """
        if (not hasattr(self.curve, 'small_curve') or
            not hasattr(self.curve, 'big_curve')):
            raise TypeError("Invalid curve.")
        _check_integer_type(scalar)
        if not self.is_valid():
            raise ValueError("Invalid input point.")
        # See comment in scalar_multiplication().
        if not scalar:
            return copy.copy(self.curve.point_at_infinity)

        # See comment in scalar_multiplication().
        if scalar < 0:
            return (-scalar) * (-self)

        # Base point on 'small curve'
        small_base_point = self.curve.small_curve.base_point

        c = self.fparithmetic.crt([(self.x, small_base_point.x),
                                   (self.y, small_base_point.y),
                                   (self.z, small_base_point.z)],
                                  (self.curve.p, self.curve.small_curve.p))

        # Base point on 'big curve'
        big_base_point = JacobianPoint(c[0], c[1], c[2], self.curve.big_curve)

        # q = scalar * big_base_point
        q = big_base_point._scalar_multiplication(scalar, _bit_length(scalar))
        invk = _FpArithmetic(self.curve.small_curve.n).inverse(scalar)

        # r = 1/k * small_q - small_base_point
        small_q = JacobianPoint(q.x, q.y, q.z, self.curve.small_curve)
        r = small_q._scalar_multiplication(invk, _bit_length(invk))
        r = r - small_base_point
        r.normalize()
        # Expected to have c=1
        c = r.x * r.y
        # Return c * this_q (with this_q is q on the current curve)
        this_q = JacobianPoint(q.x, q.y, q.z, self.curve)
        return this_q._scalar_multiplication(c, _bit_length(c))

    def __mul__(self, scalar):
        """
        Returns scalar * self with self a curve point.

        The choice of the underlying scalar multiplication algorithm will
        depend on the instantiated curve type. If the curve supports checking
        the result it will call scalar_multiplication_infective() otherwise
        scalar_multiplication() will be called.
        """
        if self.curve.check_correctness:
            return self.scalar_multiplication_infective(scalar)
        return self.scalar_multiplication(scalar)

    def __rmul__(self, scalar):
        return self.__mul__(scalar)

    def __neg__(self):
        return JacobianPoint(self.x, -self.y % self.curve.p, self.z, self.curve)

    def __eq__(self, point):
        """
        Returns True when the two points are equals. The compared points could
        have to be modified in-place in order to obtain an equivalent
        representation facilitating their comparison.
        """
        if not isinstance(point, JacobianPoint):
            raise TypeError("Invalid type %s, expected type %s." % \
                                (type(point), JacobianPoint))
        self.normalize()
        point.normalize()
        return (self.x == point.x) & (self.y == point.y) & (self.z == point.z)

    def __ne__(self, point):
        return not self.__eq__(point)

    def __copy__(self):
        return JacobianPoint(self.x, self.y, self.z, self.curve)

    def __str__(self):
        return "(%d : %d : %d)" % (self.x, self.y, self.z)

    def __repr__(self):
        return "<%d : %d : %d>" % (self.x, self.y, self.z)


class _Curve:
    def __init__(self, a, b, p, gx, gy, gz, n, h):
        """
        Weierstrass curve: Y^2 = X^3 + aXZ^4 + bZ^6 over prime field Fp
        Base point: base_point = (gx, gy, gz)
        order(base_point): n and its cofactor h

        Actually this class is private because there is currently no method
        implemented for checking their validity. It is important though to
        avoid constructing a new curve from this class without validating
        its parameters. Instead prefer calling a factory method such as
        secp256r1_curve() it will automatically builds a standardized curve
        out of knowns and validated parameters. Also do not accept
        parameters/curves settings from another party, never. Always use your
        own curves and be sure the remote party is informed of your choices.
        """
        self.a = a
        self.b = b
        self.p = p
        self.point_at_infinity = JacobianPoint(1, 1, 0, self)
        self.base_point = JacobianPoint(gx, gy, gz, self)
        # Fixme: implement an order() method in JacobianPoint class?
        self.n = n  # order(base_point)
        self.h = h  # cofactor
        self.check_correctness = False

    def set_check_correctness(self, on):
        self.check_correctness = on


def secp256r1_curve():
    """
    Factory function returning a secp256r1 curve (see
    http://www.secg.org/download/aid-784/sec2-v2.pdf). This object can be
    manipulated as a singleton and can be reused with different points.

    As scalar multiplication algorithm it will use
    JacobianPoint.scalar_multiplication (that means no formal checking of its
    result).
    """
    # Field size p = 2**256 - 2**224 + 2**192 + 2**96 - 1
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    # Curve parameters
    a = -3
    b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
    # Base point G
    gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
    gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109
    gz = 1
    # order(G)
    n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    # cofactor
    h = 1
    return _Curve(a, b, p, gx, gy, gz, n, h)

def _secp112r1_curve():
    """
    /!\ Do not use this curve.
    """
    # p = (2**128 - 3) / 76439
    p = 4451685225093714772084598273548427
    # Curve parameters
    a = 4451685225093714772084598273548424
    b = 2061118396808653202902996166388514
    # Base point G
    gx = 188281465057972534892223778713752
    gy = 3419875491033170827167861896082688
    gz = 1
    # order(G)
    n = 4451685225093714776491891542548933
    # cofactor
    h = 1
    return _Curve(a, b, p, gx, gy, gz, n, h)

def _p256r1_p112r1_curve():
    """
    /!\ Do not use this curve.
    """
    p = 515469932720476258852872762459232071402282041181133060692276609199472304430892366893122516146966316701371785077
    a = 159842626263202500189511064820427587531906528835200512373105474359642778563901551336718126411233842142655446061818598002593123907123784073049135
    b = 484889491320735356329226626040208483611546569865294753617259762389829050609800549988015429153790970160257840085
    gx = 69387807193038620347826017107789675363942498000472348441314647750703812303234318768266908719566927173922489149
    gy = 449940845877401129805638119773664617939857118052151782212917166954513344116745329959639883494500827822653780385
    gz = 1
    # Not used
    n = 0
    h = 0
    return _Curve(a, b, p, gx, gy, gz, n, h)

def secp256r1_curve_with_correctness_check():
    """
    This curve uses auxiliary curves to ensure scalar multiplication results
    are mathematically correct. Use this curve when you expect secp256r1_curve()
    returning a valid result.

    Example:
        curve = wcurve.secp256r1_curve_with_correctness_check()
        sk = random.SystemRandom().randint(1, curve.n - 1)
        # Contrarily to secp256r1_curve() the internal scalar multiplication
        # will check the correctness of its result before returning it. Be aware
        # extra-operation has a noticeable computational cost. The method
        # called internally is JacobianPoint.scalar_multiplication_infective().
        pk1 = sk * curve.base_point
        # Despite this verification the result is expected to be the same than
        # with the traditional algorithm.
        pk2 = curve.base_point.scalar_multiplication(sk)
        assert pk1 == pk2
    """
    p256r1 = secp256r1_curve()
    p256r1.set_check_correctness(True)
    p256r1.small_curve = _secp112r1_curve()
    p256r1.big_curve = _p256r1_p112r1_curve()
    return p256r1
