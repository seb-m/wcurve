#!/bin/bash
PYTHON=python

$PYTHON setup.py register
$PYTHON setup.py sdist upload --sign
$PYTHON setup.py build_sphinx
$PYTHON setup.py upload_sphinx
