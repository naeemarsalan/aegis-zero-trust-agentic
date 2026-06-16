#!/bin/sh
# Compile + run the Phase A fixture inside a fresh privileged container so each MODE
# gets its OWN mount namespace (so topology setup doesn't bleed between runs).
# Usage: run.sh            -> runs all modes
#        run.sh <mode>     -> single mode (buggy|private|slave|none)
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
IMG="alpine:latest"
TOPOS="${TOPOS:-external local}"
MODES="${1:-buggy private slave none}"

for topo in $TOPOS; do
 for mode in $MODES; do
  echo "============================================================"
  echo "TOPO: $topo   MODE: $mode"
  echo "============================================================"
  docker run --rm --privileged \
    -v "$DIR/fixture.c:/fixture.c:ro" \
    -e "TOPO=$topo" \
    "$IMG" sh -c '
      apk add --no-cache build-base >/dev/null 2>&1
      cc -O2 -Wall -Wextra -o /fixture /fixture.c
      exec /fixture "'"$mode"'"
    ' || echo "(exit $?)"
  echo
 done
done
