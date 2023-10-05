#!/bin/bash
set -e -u -x
python_versions=("38" "39" "310" "311")
PLAT="$1"

function repair_wheel {
    wheel="$1"
    if ! auditwheel show "$wheel"; then
        echo "Skipping non-platform wheel $wheel"
    else
        auditwheel repair "$wheel" --plat "$PLAT" -w /io/dist/
    fi
}

yum install -y keyutils-libs-devel

# Compile wheels
for version in "${python_versions[@]}"; do
    PYBIN="/opt/python/cp$version-cp$version/bin"
    "${PYBIN}/pip" install cython
    "${PYBIN}/pip" wheel /io/ --no-deps -w dist/
    repair_wheel dist/*-cp$version-cp$version*whl
done
