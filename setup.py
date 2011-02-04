#!/usr/bin/env python
import sys
if sys.version_info < (2, 4):
    sys.stderr.write('This module requires at least Python 2.4\n')
    sys.exit(1)

from distutils.core import setup

classif = [
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Natural Language :: English',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.4',
    'Programming Language :: Python :: 2.5',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.0',
    'Programming Language :: Python :: 3.1',
    'Programming Language :: Python :: 3.2',
    'Topic :: Security',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries',
    ]

setup(
    name='wcurve',
    version='0.1.5',
    description=('wcurve implements basic arithmetic operations on elliptic'
                 ' curves in short Weiertsrass form.'),
    author='Sebastien Martini',
    author_email='seb@dbzteam.org',
    license='MIT License',
    classifiers=classif,
    url='http://github.com/seb-m/wcurve',
    py_modules=['wcurve'],
    )
