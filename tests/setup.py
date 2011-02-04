#!/usr/bin/env python
import sys
from distutils.core import setup, Extension

assert sys.version_info >= (2, 4)

ext_mod = [Extension('ecref', libraries=['crypto'], sources=['ec_ref.c'])]
setup(ext_modules=ext_mod, py_modules=['wcurve_unittest'])
