#!/usr/bin/env bash
# Shared toolchain setup for the Linux CI jobs (GitHub-hosted ubuntu-24.04, 2 vCPU / 7 GB).
#   - Ubuntu 24.04 ships OpenSSL 3.0, but WaveX's QUIC transport needs >= 3.5, so 3.5 is built from the
#     official tarball (SHA-256 verified) into $OPENSSL_PREFIX. The CI job caches that prefix.
#   - CMake >= 4.0 comes from Kitware's official PyPI wheel.
set -euo pipefail

OPENSSL_VERSION="3.5.4"
OPENSSL_SHA256="967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$HOME/openssl-${OPENSSL_VERSION}}"
CMAKE_VERSION="4.4.4"

sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends g++-14 ninja-build ccache zlib1g-dev python3-pip

python3 -m pip install --user --break-system-packages "cmake==${CMAKE_VERSION}"
echo "$HOME/.local/bin" >> "${GITHUB_PATH:-/dev/null}"

if [ ! -f "${OPENSSL_PREFIX}/lib/libssl.so" ]; then
    work="$(mktemp -d)"
    curl -sSfL -o "${work}/openssl.tar.gz" \
        "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
    echo "${OPENSSL_SHA256}  ${work}/openssl.tar.gz" | sha256sum -c -
    tar -xzf "${work}/openssl.tar.gz" -C "${work}"
    (cd "${work}/openssl-${OPENSSL_VERSION}" &&
        ./Configure --prefix="${OPENSSL_PREFIX}" --libdir=lib no-docs no-tests shared >/dev/null &&
        make -j"$(nproc)" >/dev/null && make install_sw >/dev/null)
    rm -rf "${work}"
fi
echo "OPENSSL_PREFIX=${OPENSSL_PREFIX}" >> "${GITHUB_ENV:-/dev/null}"
