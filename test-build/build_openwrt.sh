#! /bin/bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
source "${BASEDIR}/build_inc.sh"

OPENWRT_vars_init

[[ "$(hostname)" != "debian-10-6" ]] && ERREXIT "Execute on debian22016"

[[ "$VER" != "$OWRT_PKG_VERSION" ]] || [[ "$HASH" != "$OWRT_PKG_HASH" ]] && OPENWRT_update_makefile

cp "${FILE}" "${OPENWRTDIR}/dl"

cd "$OPENWRTDIR" && nice make -j1 package/gsocket/clean &&  make -j1 V=sc package/gsocket/compile && exit 0

# FAILED
exit 255