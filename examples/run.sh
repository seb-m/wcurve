#!/bin/bash
#
# This script instruments ecdsa.py

py_lst=(/home/ookoi/Bureau/pypy-1.4.1-linux/bin/pypy python2.4 \
    python2.5 python2.6 python2.7 python3.1)
py_lst_len=${#py_lst[*]}

i=0
while [ $i -lt $py_lst_len ]; do
    cmd="${py_lst[$i]} ecdsa.py"
    echo ">> $cmd"
    $cmd
    echo
    let i++
done

exit 0
