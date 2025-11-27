#!/bin/bash
set -ex


export EL_MAJOR_VER="${EL_MAJOR_VER:-9.5}"
export EL_VER="${EL_VER:-${EL_MAJOR_VER}}"
export MAJOR_VER="${EL_VER%%.*}"
export MINOR_VER="${EL_VER#*.}"

IS_EDGE="${IS_EDGE:-0}"
VERBOSE="${VERBOSE:-1}"

mock_args=()

if [ "${VERBOSE}" -eq 1 ]; then
  mock_args+=(-v)
else
  mock_args+=(-q)
fi

function get_kvers {
    REPO_PATH="$1"
    curl "${REPO_PATH}/devel/x86_64/os/Packages/k/" | \
        grep -e 'kernel-devel-[0-9]' | \
        grep -o 'href="[^"]*\.rpm"' | \
        cut -d'"' -f2 | \
        sed -e 's/^[a-z-]*//g' | \
        sed -e 's/\.el.*//g' | \
        sort -V
}

function get_latest_kver {
    get_kvers "$1" | tail -n1
}

function get_oldest_kver {
    get_kvers "$1" | head -n1
}

function repo_addr {
    REPO_BASE="$1"
    REPO_NAME="$2"
    echo "${REPO_BASE}/${REPO_NAME}/x86_64/os/"
}

RELEASE=${RELEASE:-0}
if [ "${RELEASE}" == "1" ]; then
    RELEASE_OPT=(--define "_release ${RELEASE}")
else
    RELEASE_OPT=()
fi

if [ "${IS_EDGE}" -eq 1 ]; then
    REPO_ROOT_PATH="pub"
else
    REPO_ROOT_PATH="vault"
fi

REPO_BASE="http://download.rockylinux.org/${REPO_ROOT_PATH}/rocky/${EL_VER}"

# if we haven't injected the KVERSION we want into the env, detect it based on the repo path
if [ -z "${KVERSION}" ]; then
    if [ "${REPO_ROOT_PATH}" = "pub" ]; then
        # unfortunately we HAVE to use the latest version
        KVERSION="$(get_latest_kver "${REPO_BASE}")"
    else
        KVERSION="$(get_oldest_kver "${REPO_BASE}")"
    fi
fi

if [[ "${1}" == 'get-kvers' ]]; then
    get_kvers "${REPO_BASE}"
    exit 0
fi

echo "Starting Build $BUILD_DISPLAY_NAME on $NODE_NAME"

(git repack -a -d && rm .git/objects/info/alternates) || true

cat <<EOF >scoutfs-build-${EL_VER}.cfg
config_opts['root'] = 'rocky-${EL_VER}-base-x86_64'
config_opts['target_arch'] = 'x86_64'
config_opts['legal_host_arches'] = ('x86_64',)
config_opts['chroot_setup_cmd'] = 'install tar gcc-c++ redhat-rpm-config redhat-release which xz sed make bzip2 gzip gcc coreutils unzip shadow-utils diffutils cpio bash gawk rpm-build info patch util-linux findutils grep systemd sparse'
config_opts['dist'] = 'el${MAJOR_VER}'  # only useful for --resultdir variable subst
config_opts['releasever'] = '${MAJOR_VER}'
config_opts['package_manager'] = 'dnf'
config_opts['extra_chroot_dirs'] = [ '/run/lock', ]
config_opts['bootstrap_image'] = "quay.io/rockylinux/rockylinux:${EL_VER}"
config_opts['description'] = "Rocky Linux ${EL_VER}"
config_opts['http_proxy'] = 'http://package-mirror.vpn.versity.com:3128'

# experiment: simplify for better docker use
config_opts['use_nspawn'] = False
config_opts['isolation'] = 'simple'
config_opts['plugin_conf']['root_cache_enable'] = True
config_opts['plugin_conf']['yum_cache_enable'] = True
config_opts['plugin_conf']['dnf_cache_enable'] = True

config_opts['dnf.conf'] = """
[main]
keepcache=1
debuglevel=2
reposdir=/dev/null
logfile=/var/log/yum.log
retries=20
obsoletes=1
gpgcheck=0
assumeyes=1
syslog_ident=mock
syslog_device=
metadata_expire=0
mdpolicy=group:primary
best=1
install_weak_deps=0
protected_packages=
module_platform_id=platform:el${MAJOR_VER}
user_agent={{ user_agent }}

# repos
[baseos]
name=Rocky Linux ${EL_VER} - BaseOS
repo=rocky-BaseOS-${EL_VER}&arch=x86_64
baseurl=$(repo_addr "${REPO_BASE}" "BaseOS")
gpgcheck=0
enabled=1
gpgkey=file:///usr/share/distribution-gpg-keys/rocky/RPM-GPG-KEY-Rocky-${MAJOR_VER}

[appstream]
name=Rocky Linux ${EL_VER} - AppStream
baseurl=$(repo_addr "${REPO_BASE}" "AppStream")
gpgcheck=0
enabled=1
gpgkey=file:///usr/share/distribution-gpg-keys/rocky/RPM-GPG-KEY-Rocky-${MAJOR_VER}

[devel]
name=Rocky Linux ${EL_VER} - Devel
repo=rocky-Devel-${EL_VER}&arch=x86_64
baseurl=$(repo_addr "${REPO_BASE}" "devel")
gpgcheck=0
enabled=1
gpgkey=file:///usr/share/distribution-gpg-keys/rocky/RPM-GPG-KEY-Rocky-${MAJOR_VER}

[epel]
name=EPEL - \$releasever
baseurl=https://dl.fedoraproject.org/pub/epel/\$releasever/Everything/x86_64/
gpgcheck=0
enabled=1
"""
EOF

cd "${WORKSPACE:-.}"

sudo mkdir -p /usr/share/distribution-gpg-keys/rocky/
sudo curl -o "/usr/share/distribution-gpg-keys/rocky/RPM-GPG-KEY-Rocky-${MAJOR_VER}" https://download.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-${MAJOR_VER}

# make kmod rpms
pushd kmod
rm kmod-scoutfs.spec || true
make dist
if [ "$?" -ne "0" ]; then
    exit 1
fi

sleep 5s

try=0
while [[ "$try" -lt "3" ]]; do
    echo "Trying to build srpm; attempt #$try"
    set +e
    SRPM=$(rpmbuild -ts "${RELEASE_OPT[@]}" --define "kversion ${KVERSION}.el${EL_VER//./_}.x86_64" --define "dist .el${MAJOR_VER}" scoutfs-kmod-*.tar | awk '{print $2}' )
    set -e
    if [ -f "$SRPM" ]; then
        echo "SRPM created: $SRPM"
        break
    fi
    try="$((try + 1))"
    sleep 5s
done

if [ -z "$SRPM" ]; then
    echo "no srpm found."
    exit 1
fi

if [ "${MAJOR_VER}" -gt 7 ] ; then
  mock_args+=(--dnf)
else
  mock_args+=(--yum)
fi

mock "${mock_args[@]}" --enablerepo epel -r "../scoutfs-build-${EL_VER}.cfg" rebuild "${RELEASE_OPT[@]}" --define "kversion ${KVERSION}.el${EL_VER//./_}.x86_64" --define "dist .el${EL_VER//./_}" --resultdir "./scoutfs_${EL_VER//./_}" "${SRPM}"
if [ "$?" -ne "0" ]; then
    exit 1
fi

popd

# make utils rpms
pushd utils
make dist
if [ "$?" -ne "0" ]; then
    exit 1
fi

SRPM=$(rpmbuild -ts "${RELEASE_OPT[@]}" --define "dist .el${MAJOR_VER}" scoutfs-utils-*.tar | awk '{print $2}')
if [ -z "$SRPM" ]; then
    echo "no srpm found."
    exit 1
fi

mock "${mock_args[@]}" --enablerepo epel -r "../scoutfs-build-${EL_VER}.cfg" rebuild "${RELEASE_OPT[@]}" --define "dist .el${MAJOR_VER}" --resultdir "./scoutfs_${EL_VER//./_}" "${SRPM}"
if [ "$?" -ne "0" ]; then
    exit 1
fi

popd

#gpg --export -a 'Versity Software' > RPM-GPG-KEY-scoutfs

exit 0

