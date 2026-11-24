#!/bin/sh
set -e
mkdir -p dist
tar -cf dist/src.tar src
sha256sum dist/src.tar > dist/SHA256SUMS
cat dist/SHA256SUMS
