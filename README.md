# wcurve

* Project URL   : [http://github.com/seb-m/wcurve](http://github.com/seb-m/wcurve)
* Documentation : [http://seb-m.github.com/wcurve](http://seb-m.github.com/wcurve)
* Dependencies  : Python ≥ 2.4
* License       : MIT


## Description

This package implements basic arithmetic operations such as point addition and
single-scalar multiplication on elliptic curves in short Weiertsrass form.

### Example

    import wcurve, random
    # Instantiate secp256r1 standardized curve
    curve  = wcurve.secp256r1_curve()
    # Generate a new secret value
    sk = random.SystemRandom().randint(1, curve.n - 1)
    # Compute the public key associated to the previous secret
    pk = sk * curve.base_point
    # Get its affine coordinates
    pkx, pky = pk.to_affine()


## Install

    # From tarball
    $ sudo python setup.py install
    # Or with setuptools
    $ sudo easy_install wcurve


## Run tests

    $ make test


## Build Documentation

The current documentation is built with Sphynx, just use this command to
generate it:

    $ cd doc/ && make html
