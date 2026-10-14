#!/bin/sh
set -eu

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "usage: verify.sh DIST_DIR PUBLIC_KEY [VERSION]" >&2
  exit 2
fi
dist_dir="$1"
pub="$2"
version="${3:-}"
sums="$dist_dir/SHA256SUMS"

if ! command -v minisign >/dev/null 2>&1; then
  echo "verify: minisign is required" >&2
  exit 1
fi
if [ ! -f "$sums" ] || [ ! -f "$sums.minisig" ]; then
  echo "verify: $sums and $sums.minisig are required" >&2
  exit 1
fi
if [ ! -f "$pub" ]; then
  echo "verify: public key $pub not found" >&2
  exit 1
fi

out=$(minisign -V -p "$pub" -m "$sums" -x "$sums.minisig")
printf '%s\n' "$out"
if [ -n "$version" ]; then
  case "$out" in
    *"Trusted comment: pairier $version SHA256SUMS"*) ;;
    *)
      echo "verify: trusted comment does not name version $version" >&2
      exit 1
      ;;
  esac
fi

cd "$dist_dir"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c SHA256SUMS
else
  shasum -a 256 -c SHA256SUMS
fi
