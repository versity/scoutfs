#!/bin/bash

set -e

. /etc/os-release

MAJOR_VER="${VERSION_ID%%.*}"

if [[ "$VERSION_ID" == *.* ]]; then
    MINOR_VER=".${VERSION_ID#*.}"
else
    MINOR_VER=""
fi
DISTRO="${ID}"

IS_EDGE="${IS_EDGE:-0}"

if [ "${IS_EDGE}" = 0 ]; then
  PUB_OR_VAULT=vault
else
  PUB_OR_VAULT=pub
fi

VAULT_PREFIX=""
PUB_PREFIX=""

# - Accept ${SKIP_REPO_FIXUP} to take no action at all
# - Accept ${IS_EDGE} as 1/0 for whether we should lock to the *vaulted* repo vs. the current public one

if [ "${SKIP_REPO_FIXUP}" = 'true' ]; then
  echo "Requested to take no action on repositories; exiting cleanly"
  exit 0
fi

case ${DISTRO} in
  rocky)
    PUB_PREFIX="http://download.rockylinux.org/${PUB_OR_VAULT}/rocky"
    VAULT_PREFIX="${PUB_PREFIX}"
    RELEASE="${MAJOR_VER}${MINOR_VER}"
    ;;
  centos)
    PUB_PREFIX="http://mirror.centos.org/centos"
    VAULT_PREFIX="http://vault.centos.org"
    RELEASE="$(cat /etc/redhat-release |awk '{print $4}')"
    ;;
  oracle)
    echo "TODO"
    ;;
  *)
    echo "Unknown distro, unsure how to remap repos- exiting cleanly without doing anything"
    exit 0
    ;;
esac

if [ "${IS_EDGE}" = 0 ]; then
  BASE_URL="${VAULT_PREFIX}/${RELEASE}"
else
  BASE_URL="${PUB_PREFIX}/${RELEASE}"
fi

for repo in "/etc/yum.repos.d/"*; do
  sed -i -e "s/^mirrorlist/#mirrorlist/g" -e "s/^#baseurl/baseurl/g" \
    -e "s|^metalink|#metalink|g" -e "s|https|http|g" "$repo"
  if ! [[ "$repo" =~ .*epel.* ]]; then
    sed -i -e "s|http.*releasever|${BASE_URL}|g" "$repo"
    if [ "${IS_EDGE}" = 0 ]; then
      sed -i -e "s|pub|vault|g" "$repo"
    fi
  else
    sed -i -e "s|download.example|archives.fedoraproject.org|g" "$repo"
    if [ "${IS_EDGE}" = 0 ]; then
      sed -i -e "s|pub/epel/${MAJOR_VER}|pub/archive/epel/${VERSION_ID}|g" "$repo"
    fi
  fi
done

if [ "${MAJOR_VER}" -gt "7" ]; then
  dnf clean metadata
  dnf clean all
else
  yum clean metadata
  yum clean all
fi
