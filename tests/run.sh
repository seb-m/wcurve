#!/bin/bash
#
# This script runs tests

py_lst=(pypy \
        python2.4 \
        python2.5 \
        python2.6 \
        python2.7 \
        python3.1 \
        python3.2)
py_lst_len=${#py_lst[*]}

i=0
while [ $i -lt $py_lst_len ]; do
    bin=`command -v ${py_lst[$i]}`
    let i++

    if [ -z $bin ]; then
	continue
    fi

    echo ">> Testing with $bin"
    $bin setup.py --quiet build
    $bin wcurve_unittest.py
    # fixme: --quiet is not fully quiet
    $bin setup.py --quiet clean --all 2>/dev/null 1>&2
    # fixme: make it clean by setup.py
    rm -f openssl_ec.so
    echo
done

exit 0
