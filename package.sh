#!/usr/bin/sh

docker run --rm -v "$(pwd)":/io quay.io/pypa/manylinux_2_28_x86_64 /io/buildwheels.sh manylinux_2_28_x86_64
