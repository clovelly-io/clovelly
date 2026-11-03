#!/usr/bin/env bash
# Runs Nix with flakes for builds of this repository.
#
#   release/nix.sh <nix args...>          run nix with flakes enabled
#   release/nix.sh build-to <attr> <dir>  build a flake attr and copy its output to <dir>
#
# Uses a native `nix` when one is installed. Otherwise runs the pinned nixos/nix
# container as x86_64-linux, with the repo at /src and the store in the `clovelly-nix`
# Docker volume so it persists between runs.
#
# Image builds sign the UKI with the Secure Boot db key, so the build is --impure and
# CLOVELLY_SIGNING_KEYS names the key directory, outside the repository.
# Without that directory (a CI runner, a rebuilder) builds are pure, and only the
# unsigned images and other attributes that need no key can be built.
#
#   CLOVELLY_NIX_VOLUME=<name>   use another store volume (a second, independent builder)
set -euo pipefail

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
image=nixos/nix:2.28.3@sha256:e623d73af9cac82d1b50784c83e0cf2a4b83bfd2cfe8d5b67809a2fc94e043ac
keys=${CLOVELLY_SIGNING_KEYS:-}
volume=${CLOVELLY_NIX_VOLUME:-clovelly-nix}
impure=""
[ -d "$keys" ] && impure=--impure

# Runs wherever nix lives, with the repo as the working directory.
inner='
set -euo pipefail
nixc() { nix --extra-experimental-features "nix-command flakes" $EXTRA "$@"; }
if [ "$1" = build-to ]; then
  out=$(nixc build $IMPURE --no-link --print-out-paths --print-build-logs ".#$2")
  rm -rf "$3" && mkdir -p "$3"
  if [ -d "$out" ]; then cp -rL "$out"/. "$3"/; else cp -L "$out" "$3"/; fi
  chmod -R u+w "$3"
  echo "$out" > "$3/.store-path"
  # In the container the copy belongs to root: give it to the caller (a Linux host;
  # Docker Desktop maps owners itself and may refuse).
  if [ -n "${HOST_UID:-}" ]; then chown -R "$HOST_UID:$HOST_GID" "$3" 2>/dev/null || true; fi
else
  nixc "$@"
fi'

if command -v nix >/dev/null; then
  cd "$repo"
  CLOVELLY_SIGNING_KEYS=$keys IMPURE=$impure EXTRA='' exec bash -c "$inner" bash "$@"
fi

# In a git worktree, .git is a file naming the main repository's git directory by its
# absolute path, which names the worktree by its own: mount both at their real paths
# (the shared git directory read-only) so the flake's git tree resolves.
src=/src
gitmounts=()
if [ -f "$repo/.git" ]; then
  src=$repo
  common=$(cd "$repo" && cd "$(git rev-parse --git-common-dir)" && pwd)
  gitmounts=(-v "$common":"$common":ro)
fi

keymount=()
[ -n "$impure" ] && keymount=(-v "$keys":/keys:ro -e CLOVELLY_SIGNING_KEYS=/keys)
exec docker run --rm -i --platform linux/amd64 -v "$volume":/nix -v "$repo":"$src" ${gitmounts[@]+"${gitmounts[@]}"} -w "$src" \
  ${keymount[@]+"${keymount[@]}"} -e IMPURE="$impure" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -e EXTRA="--option sandbox false --option filter-syscalls false --option max-jobs auto --option cores 0" \
  "$image" bash -c "git config --global --add safe.directory '$src'; $inner" bash "$@"
