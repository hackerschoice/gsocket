#! /bin/bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
source "${BASEDIR}/../../test-build/build_inc.sh"

OPENWRT_vars_init

[[ ! -d "$OWRT_FEEDDIR" ]] && ERREXIT "Not found: $OWRT_FEEDDIR"

OPENWRT_update_makefile

cp "${BASEDIR}/gsocket/Makefile" "${OWRT_FEEDDIR}"

echo "Press enter to push release $VER"
read
(cd "$OWRT_FEEDDIR" && \
	git commit --amend --no-edit --signoff -m "gsocket: upstream update to $VER" && \
	git push --force-with-lease origin master)


