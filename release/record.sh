#!/usr/bin/env bash
# Writes the build record (build.txt) of the unsigned images in DIR/prod and DIR/test,
# as built by release/rebuild.sh: the lines the compare gate diffs and a rebuilder
# compares with a release's Rekor payload (crates/rebuild/src/record.rs).
#
#   release/record.sh DIR BUILDER     BUILDER: github-hosted, gce/<project> or independent
#
# Prints the record and writes it to DIR/build.txt. Uses bash and coreutils only (the
# pinned nixos/nix container has no sed). Written for bash 3.2.
set -euo pipefail

dir=$1 builder=$2
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
# The value of KEY= in FILE.
value() {
  local line
  while IFS= read -r line; do
    case $line in "$1="*) printf '%s\n' "${line#"$1="}"; return 0 ;; esac
  done < "$2"
  return 1
}
{
  echo "builder=$builder"
  echo "commit=$(git -C "$repo" rev-parse HEAD)"
  for v in prod test; do
    d=$dir/$v
    echo "$v.release=$(cat "$d/release")"
    echo "$v.recipe=$(cat "$d/recipe")"
    echo "$v.disk_sha256=$(cat "$d/disk.sha256")"
    echo "$v.tarball_sha256=$(sha "$d/disk.raw.tar.gz")"
    echo "$v.rtmr1=$(value rtmr1 "$d/predicted-rtmr")"
    echo "$v.rtmr2=$(value rtmr2 "$d/predicted-rtmr")"
  done
  while IFS= read -r line; do echo "version.$line"; done < "$dir/prod/versions"
} > "$dir/build.txt"
cat "$dir/build.txt"
