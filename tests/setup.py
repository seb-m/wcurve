#!/usr/bin/env python
import sys
from distutils.core import setup, Extension

assert sys.version_info >= (2, 4)

ext_mod = [Extension('openssl_ec', libraries=['crypto'],
                     sources=['openssl_ec.c'])]
setup(ext_modules=ext_mod, py_modules=['wcurve_unittest'])
