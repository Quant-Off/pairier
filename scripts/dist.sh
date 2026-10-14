#!/bin/sh
set -eu

version="$1"
core_bin="$2"
kmsd_bin="$3"
kmsctl_bin="$4"
out_dir="$5"
epoch="${SOURCE_DATE_EPOCH:-0}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
esac
name="pairier-${version}-${os}-${arch}"

if tar --version 2>/dev/null | grep -q GNU; then
  TAR=tar
elif command -v gtar >/dev/null 2>&1; then
  TAR=gtar
else
  echo "dist: GNU tar is required for reproducible archives (brew install gnu-tar)" >&2
  exit 1
fi

stage="$out_dir/$name"
rm -rf "$stage"
mkdir -p "$stage"
cp "$core_bin" "$stage/kms-core"
cp "$kmsd_bin" "$stage/kmsd"
cp "$kmsctl_bin" "$stage/kmsctl"
chmod 0755 "$stage"/*
"$stage/kms-core" --version > "$stage/VERSION"
"$stage/kmsd" --version >> "$stage/VERSION"
"$stage/kmsctl" version >> "$stage/VERSION"
chmod 0644 "$stage/VERSION"

(
  cd "$out_dir"
  find "$name" -print0 | LC_ALL=C sort -z | \
    "$TAR" --null --no-recursion --files-from=- \
      --owner=0 --group=0 --numeric-owner \
      --mtime="@$epoch" --format=gnu \
      -cf - | gzip -n -9 > "$name.tar.gz"
  rm -rf "$name"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$name.tar.gz" > "$name.tar.gz.sha256"
  else
    shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256"
  fi
  cat ./*.tar.gz.sha256 | LC_ALL=C sort > SHA256SUMS
)
echo "$out_dir/$name.tar.gz"
