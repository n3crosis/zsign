#!/bin/sh
# Requires C++11, pkg-config, OpenSSL 3 development files, Python 3 and openssl.
# Uses only disposable identities and generated Mach-O bytes. No Apple account,
# network, Xcode, device or signing credentials are needed.
set -eu
export PYTHONDONTWRITEBYTECODE=1
cd "$(dirname "$0")/.."
build=$(mktemp -d "${TMPDIR:-/tmp}/zsign-library-tests.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
${CXX:-c++} -std=c++11 -fPIC -shared -O2 -pthread -Isrc -Isrc/common \
    $(pkg-config --cflags openssl) \
    src/library.cpp src/identity.cpp src/archo.cpp src/signing.cpp src/openssl.cpp \
    src/common/fs.cpp src/common/json.cpp src/common/log.cpp src/common/sha.cpp \
    src/common/timer.cpp src/common/util.cpp \
    $(pkg-config --libs openssl) -o "$build/libzsign.so"
python3 tests/test_signer_bridge.py "$build/libzsign.so"
ZSIGN_LIBRARY="$build/libzsign.so" python3 -m unittest discover -s tests -p 'test_ios_identity_validation.py' -v
