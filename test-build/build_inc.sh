#! /bin/bash

ERREXIT()
{
	echo >&2 "ERROR: $@"
	exit 255
}

OPENWRT_vars_init()
{
	OPENWRTDIR="$HOME/openwrt"
	MKFILE="${TOPDIR}/packaging/openwrt/gsocket/Makefile"
	OWRT_PKG_VERSION="$(grep ^PKG_VERSION: "${MKFILE}" | cut -f2 -d=)"
	OWRT_PKG_HASH="$(grep ^PKG_HASH: "${MKFILE}" | cut -f2 -d=)"
	# mdir ~/resarch/openwrt && cd ~/research/openwrt && git clone --depth 1 git@github.com:SkyperTHC/packages.git
	OWRT_FEEDDIR="$(cd "${TOPDIR}/../openwrt/packages" || exit; pwd)"
}

OPENWRT_update_makefile()
{
	[[ "$VER" = "$OWRT_PKG_VERSION" ]] && [[ "$HASH" == "$OWRT_PKG_HASH" ]] && return
	echo "Updating openwrt/gsocket/Makfile..."
	echo "$OWRT_PKG_VERSION => $VER"
	echo "$OWRT_PKG_HASH => $HASH"

	cp "${MKFILE}" "${MKFILE}-old"
	mk=$(sed "s/^PKG_HASH.*/PKG_HASH:=${HASH}/g" <"${MKFILE}" | sed "s/^PKG_VERSION.*/PKG_VERSION:=${VER}/g")
	echo "$mk" >"${MKFILE}"
	OWRT_PKG_VERSION="$VER"
	OWRT_PKG_HASH="$HASH"
}

find_topdir()
{
	[[ -n $TOPDIR ]] && return
	[[ ! -f "${BASEDIR}/${1}/configure.ac" ]] && return
	TOPDIR="$(cd "${BASEDIR}/${1}" || exit; pwd)"
}

find_topdir .
find_topdir ..
find_topdir ../..
find_topdir ../../..

VER="$1"
[[ -z "$1" ]] && VER="$(grep AC_INIT "${TOPDIR}/configure.ac" | cut -f3 -d"[" | cut -f1 -d']')"

FILENAME="gsocket-${VER}.tar.gz"
FILE="${TOPDIR}/${FILENAME}"

[[ -f "$FILE" ]] || ERREXIT "$FILE not found"

HASH="$(sha256sum "${FILE}" | cut -f1 -d" ")"

