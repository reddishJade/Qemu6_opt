#!/bin/sh

set -eu

dir="$1"
pkgversion="$2"
version="$3"

if [ -z "$pkgversion" ]; then
    cd "$dir"
    if [ -e .git ]; then
#        pkgversion=$(git describe --match 'v*' --dirty) || :
        pkgversion="git-$(git rev-parse --short HEAD)"
    else
	pkgversion=""
    fi
fi
#if [ -n "$pkgversion" ]; then
#    fullversion="$version ($pkgversion)"
#else
    fullversion="$version"
#fi

if [ "x"$pkgversion != "x" ]; then
    commit_ts=`git log -1 --format="%ct"`
    git_version=`git log -1 --format="%h"`
    commit_time=`date -d@$commit_ts +"%Y%m%d"`
else
    commit_ts=""
    git_version=""
    commit_time=""
fi
build_arch=`arch`
cat <<EOF
#define QEMU_PKGVERSION "$pkgversion"
#define QEMU_FULL_VERSION "$fullversion"
#define QEMU_GIT_VERSION "id: $git_version  commit_time:$commit_time"
#define QEMU_BUILD_ARCH "$build_arch"
EOF
