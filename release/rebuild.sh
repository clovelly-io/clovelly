#!/usr/bin/env bash
# The one-command rebuild (REPRODUCE.md): builds this checkout's unsigned prod and test
# images and the verifier and clovelly-keys container images, and writes their build record.
#
#   release/rebuild.sh [DIR]          default DIR: build/rebuild
#
# Needs Nix with flakes, or Docker (release/nix.sh then runs the pinned nixos/nix
# container). No signing key is needed: the unsigned images are what the release
# pipeline's two builders compare, and their RTMR1 and RTMR2 are the signed images'.
# CLOVELLY_BUILDER (default `independent`) names the builder in the record. Prints the
# record (DIR/build.txt); the cell images are in DIR/prod and DIR/test, and the container
# images, as OCI layouts with their digests, in DIR/images/verifier and DIR/images/clovelly-keys.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
dir=${1:-$repo/build/rebuild}
case $dir in /*) ;; *) dir=$PWD/$dir ;; esac
# Built from a clean tree only: the record names the commit.
[ -z "$(git -C "$repo" status --porcelain --untracked-files=no)" ] \
  || { echo "rebuild.sh: the checkout has uncommitted changes" >&2; exit 1; }
cd "$repo"
mkdir -p "$dir"
for v in prod test; do
  echo "building .#image-$v-unsigned" >&2
  # build-to copies into a path relative to the repository.
  rel=${dir#"$repo"/}
  "$repo/release/nix.sh" build-to "image-$v-unsigned" "$rel/$v" >&2
  "$repo/release/nix.sh" eval --raw ".#image-$v-unsigned.drvPath" > "$dir/$v/recipe"
done
rel=${dir#"$repo"/}
for i in verifier clovelly-keys; do
  echo "building .#$i-image-oci" >&2
  "$repo/release/nix.sh" build-to "$i-image-oci" "$rel/images/$i" >&2
done
"$here/record.sh" "$dir" "${CLOVELLY_BUILDER:-independent}"
