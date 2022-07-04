#! /bin/bash

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)" # r/gsocket/packaging/openwrt
source "${BASEDIR}/../../test-build/build_inc.sh"


OPENWRT_vars_init

[[ -z $OWRT_FEEDDIR ]] && ERREXIT "OWRT_FEEDDIR is empty. ~/research/openwrt not exist?"

[[ ! -d "$OWRT_FEEDDIR/net/gsocket" ]] && mkdir -p "${OWRT_FEEDDIR}/net/gsocket"
OPENWRT_update_makefile

# from r/gsocket/packaging/openwrt/gsocket/* to /r/openwrt/packages/net/gsocket
cp "${BASEDIR}/gsocket/Makefile" "${OWRT_FEEDDIR}/net/gsocket"
cp "${BASEDIR}/gsocket/test.sh" "${OWRT_FEEDDIR}/net/gsocket"

echo "Press enter to push release $VER"
read
(cd "$OWRT_FEEDDIR/net/gsocket" && \
	git add Makefile test.sh && \
	git commit --amend --author="Ralf Kaiser <root@thc.org>" --no-edit --signoff -m "gsocket: upstream update to $VER" && \
	git push --force-with-lease origin master)


