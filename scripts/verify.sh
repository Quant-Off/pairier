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
if [ ! -s SHA256SUMS ]; then
  echo "verify: SHA256SUMS is empty" >&2
  exit 1
fi
if grep -Evq '^[0-9a-f]{64}  [A-Za-z0-9._+-]+$' SHA256SUMS; then
  echo "verify: SHA256SUMS contains a malformed line" >&2
  exit 1
fi
listed=$(sed 's/^[0-9a-f]*  //' SHA256SUMS)
for f in ./*.tar.gz ./*.cdx.json; do
  [ -e "$f" ] || continue
  name=${f#./}
  if ! printf '%s\n' "$listed" | grep -Fxq -- "$name"; then
    echo "verify: $name is not covered by SHA256SUMS" >&2
    exit 1
  fi
done
if [ -n "$version" ]; then
  found=0
  for name in $listed; do
    case "$name" in
      "pairier-$version-"*.tar.gz) found=1 ;;
    esac
  done
  if [ "$found" -ne 1 ]; then
    echo "verify: SHA256SUMS lists no pairier-$version tarball" >&2
    exit 1
  fi
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --strict -c SHA256SUMS
else
  shasum -a 256 --strict -c SHA256SUMS
fi
