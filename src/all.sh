#!/bin/bash

CDPATH=
SCRIPT_BASE=$(dirname "$0")
cd "$SCRIPT_BASE"

( mkdir -p build && cd build && cmake .. )

make -s -C build/ && make -s -C build/test/ all test
