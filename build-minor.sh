#!/bin/bash
set -e

export EL_MAJOR_VER="${EL_MAJOR_VER:-9.4}"
export EL_VER="${EL_VER:-${EL_MAJOR_VER}}"
export MAJOR_VER="${EL_VER%%.*}"
export MINOR_VER="${EL_VER#*.}"
export RELEASE="${RELEASE:-0}"
export IS_EDGE="${IS_EDGE:-0}"
export VERBOSE="${VERBOSE:-1}"
export FORCE_REBUILD_DOCKER_IMAGE="${FORCE_REBUILD_DOCKER_IMAGE:-0}"
export HTTP_PROXY="${HTTP_PROXY:-}"

if [ -z "${KVERS}" ]; then
  KVERS="$(bash build-packages.sh get-kvers)"
else
  echo "Specified the following kernel versions to build against:"
  echo "${KVERS}"
fi

# use old-style build process for el7
if [ "${MAJOR_VER}" -gt 7 ]; then
  bash build-container.sh
fi

for KVER in ${KVERS}; do
  echo "Building for ${KVER} on ${EL_VER}"
  if [ "${MAJOR_VER}" -gt 7 ]; then
    docker run --rm --privileged \
      -e "VERBOSE=${VERBOSE}" \
      -e "KVERSION=${KVER}" \
      -e "EL_VER=${EL_VER}" \
      -e "RELEASE=${RELEASE}" \
      -e "HTTP_PROXY=${HTTP_PROXY}" \
      -e "IS_EDGE=${IS_EDGE}" \
      -v "/var/cache:/var/cache" \
      -v "/run/containers/storage:/run/containers/storage" \
      -v "/var/lib/containers/storage:/var/lib/containers/storage" \
      -v .:/repo \
      "scoutfs-builder:el${EL_VER}" \
        bash -c "cd /repo && git config --global --add safe.directory /repo && bash build-packages.sh && chown -R ${UID} /repo"
  else
    # use 'legacy' build process for el7
    KVERSION="${KVER}" bash build-packages.sh
  fi
done
