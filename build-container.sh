#!/bin/bash

set -ex

export VERBOSE="${VERBOSE:-0}"
if [ "${VERBOSE}" -eq 1 ]; then
  set -x
fi
export EL_MAJOR_VER="${EL_MAJOR_VER:-9.5}"
export EL_VER="${EL_VER:-${EL_MAJOR_VER}}"
export MAJOR_VER="${EL_VER%%.*}"
export MINOR_VER="${EL_VER#*.}"
export IS_EDGE="${IS_EDGE:-0}"
export FORCE_REBUILD_DOCKER_IMAGE="${FORCE_REBUILD_DOCKER_IMAGE:-0}"

if [ -z "${MINOR_VER}" ] || [ -z "${MAJOR_VER}" ]; then
  echo "Major/minor versions could not be inferred from required version ${EL_VER}, bailing out"
  exit 1
fi

if [ "${MAJOR_VER}" -gt 7 ]; then
  IMAGE_BASE="quay.io/rockylinux/rockylinux"
  IMAGE_VERSION="${MAJOR_VER}.${MINOR_VER}-ubi"
else
  IMAGE_BASE="library/centos"
  IMAGE_VERSION="centos7.9.2009"
fi

# build fresh 'builder' images only if we don't have them or want to force a rebuild
if [ "$(docker images -q scoutfs-builder:el${MAJOR_VER}.${MINOR_VER})" == "" ] || [ "${FORCE_REBUILD_DOCKER_IMAGE}" == '1' ]; then
  docker_args=()
  if [[ "${SKIP_CACHE}" == 'true' ]]; then
    docker_args+=(--no-cache)
  fi
  docker build . "${docker_args[@]}" --build-arg IS_EDGE="${IS_EDGE}" --build-arg IMAGE_SOURCE="${IMAGE_BASE}:${IMAGE_VERSION}" -t "scoutfs-builder:el${MAJOR_VER}.${MINOR_VER}"
fi
