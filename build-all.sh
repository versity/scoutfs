#!/bin/bash

export VERBOSE="${VERBOSE:-0}"
if [ "${VERBOSE}" -eq 1 ]; then
  set -x
fi
export EL_VER
export IS_EDGE

# 'edge' releases first'
for EL_VER in 8.10 9.6; do
  IS_EDGE=1
  bash ./build-minor.sh
done

# then legacy
for EL_VER in 8.9 9.4 9.5; do
  IS_EDGE=0
  bash ./build-minor.sh
done
