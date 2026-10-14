#!/bin/sh
set -eu

if [ $# -ne 2 ]; then
  echo "usage: sign.sh DIST_DIR VERSION" >&2
  exit 2
fi
dist_dir="$1"
version="$2"
key="${MINISIGN_KEY:-$HOME/.minisign/minisign.key}"
sums="$dist_dir/SHA256SUMS"

if ! command -v minisign >/dev/null 2>&1; then
  echo "sign: minisign is required" >&2
  exit 1
fi
if [ ! -f "$sums" ]; then
  echo "sign: $sums not found (run make dist first)" >&2
  exit 1
fi
if [ ! -f "$key" ]; then
  echo "sign: secret key $key not found (set MINISIGN_KEY)" >&2
  exit 1
fi

rm -f "$sums.minisig"
minisign -S -s "$key" -m "$sums" -x "$sums.minisig" \
  -t "pairier $version SHA256SUMS" -c "pairier release signature"
echo "$sums.minisig"
