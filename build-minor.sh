#!/bin/bash
set -x

export EL_MAJOR_VER="${EL_MAJOR_VER:-9.4}"
export EL_VER="${EL_VER:-${EL_MAJOR_VER}}"
export MAJOR_VER="${EL_VER%%.*}"
export MINOR_VER="${EL_VER#*.}"
export RELEASE="${RELEASE:-0}"
export IS_EDGE="${IS_EDGE:-0}"
export VERBOSE="${VERBOSE:-1}"
export FORCE_REBUILD_DOCKER_IMAGE="${FORCE_REBUILD_DOCKER_IMAGE:-0}"

export PUB_OR_VAULT
if [ "${IS_EDGE}" = 0 ]; then
  PUB_OR_VAULT=vault
else
  PUB_OR_VAULT=pub
fi

bash build-container.sh

for KVER in $(bash build-packages.sh get-kvers); do
  echo "Building for ${KVER} on ${EL_VER}"
  docker run --rm --privileged \
    -e "VERBOSE=${VERBOSE}" \
    -e "KVERSION=${KVER}" \
    -e "EL_VER=${EL_VER}" \
    -e "RELEASE=${RELEASE}" \
    -e "HTTP_PROXY=http://package-mirror.vpn.versity.com:3128" \
    -e "IS_EDGE=${IS_EDGE}" \
    -v "/var/cache:/var/cache" \
    -v "/run/containers/storage:/run/containers/storage" \
    -v "/var/lib/containers/storage:/var/lib/containers/storage" \
    -v .:/repo \
    "scoutfs-builder:el${EL_VER}" \
      bash -c "cd /repo && git config --global --add safe.directory /repo && bash build-packages.sh && chown -R ${UID} /repo"
done
