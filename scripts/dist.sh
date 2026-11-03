#!/bin/sh
set -eu

version="$1"
core_bin="$2"
kmsd_bin="$3"
kmsctl_bin="$4"
out_dir="$5"
sbom="$6"
epoch="${SOURCE_DATE_EPOCH:-0}"
python="${PYTHON:-python3}"
root=$(cd "$(dirname "$0")/.." && pwd)

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  mingw*|msys*|cygwin*) os=windows ;;
esac
arch="${DIST_ARCH:-$(uname -m)}"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
esac
name="pairier-${version}-${os}-${arch}"
exe=""
if [ "$os" = windows ]; then
  exe=.exe
elif tar --version 2>/dev/null | grep -q GNU; then
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
cp "$core_bin" "$stage/kms-core$exe"
cp "$kmsd_bin" "$stage/kmsd$exe"
cp "$kmsctl_bin" "$stage/kmsctl$exe"
chmod 0755 "$stage"/*
"$stage/kms-core$exe" --version > "$stage/VERSION"
"$stage/kmsd$exe" --version >> "$stage/VERSION"
"$stage/kmsctl$exe" version >> "$stage/VERSION"
cp "$sbom" "$stage/sbom.cdx.json"
cp "$root/LICENSE" "$stage/LICENSE"
cp "$root/NOTICE" "$stage/NOTICE"
chmod 0644 "$stage/VERSION" "$stage/sbom.cdx.json" "$stage/LICENSE" "$stage/NOTICE"

(
  cd "$out_dir"
  if [ "$os" = windows ]; then
    archive="$name.zip"
    "$python" -I "$root/scripts/zipdist.py" "$name" "$archive" "$epoch"
  else
    archive="$name.tar.gz"
    find "$name" -print0 | LC_ALL=C sort -z | \
      "$TAR" --null --no-recursion --files-from=- \
        --owner=0 --group=0 --numeric-owner \
        --mtime="@$epoch" --format=gnu \
        -cf - | gzip -n -9 > "$archive"
  fi
  cp "$name/sbom.cdx.json" "$name.cdx.json"
  rm -rf "$name"
  if command -v sha256sum >/dev/null 2>&1; then
    sum="sha256sum"
  else
    sum="shasum -a 256"
  fi
  $sum "$archive" > "$archive.sha256"
  $sum "$name.cdx.json" > "$name.cdx.json.sha256"
  cat ./*.sha256 | LC_ALL=C sort > SHA256SUMS
  echo "$out_dir/$archive"
)
