#!/usr/bin/env bash
# Run a command against an untrusted target with bubblewrap, for local PoCs.
#
#   tools/sandbox.sh [--net] DIR COMMAND...
#
# DIR is mounted read-write at /work and is the only writable path that survives.
# The rest of the system is read-only, $HOME is an empty tmpfs, and the environment
# is cleared, so tokens and SSH keys are out of reach. Network is off unless --net
# is given; use it for installing dependencies only, never while running the target.
set -euo pipefail

net=(--unshare-net)
if [ "${1:-}" = "--net" ]; then
  net=(--share-net)
  shift
fi
[ $# -ge 2 ] || { echo "usage: $0 [--net] DIR COMMAND..." >&2; exit 2; }
dir="$(cd "$1" && pwd)"
shift

exec bwrap \
  --unshare-all "${net[@]}" --die-with-parent --new-session --clearenv \
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/bin /sbin \
  --symlink usr/lib /lib --symlink usr/lib /lib64 \
  --ro-bind /etc/ssl /etc/ssl --ro-bind /etc/ca-certificates /etc/ca-certificates \
  --ro-bind /etc/resolv.conf /etc/resolv.conf --ro-bind /etc/hosts /etc/hosts \
  --ro-bind /etc/nsswitch.conf /etc/nsswitch.conf \
  --proc /proc --dev /dev --tmpfs /tmp --tmpfs /home \
  --bind "$dir" /work --chdir /work \
  --setenv HOME /work/.home --setenv PATH /usr/bin --setenv CI 1 \
  "$@"
