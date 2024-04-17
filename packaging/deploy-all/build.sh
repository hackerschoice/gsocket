#! /usr/bin/env bash

# Used on GitHub action to build deploy-all.sh
# packaging/deploy-all/build.sh BASEDIR PKG-DIR
# packaging/deploy-all/build.sh /tmp /tmp/gs-pkg

DSTDIR="${1:?}"
SRCDIR="${2:?}"

HEAD='#! /bin/sh
ARCHIVE=`awk '"'"'/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }'"'"' $0`
mkdir .gs-pkg
tail -n+$ARCHIVE $0 | gunzip | tar x -C .gs-pkg
(cd '.gs-pkg'; GS_USELOCAL=1 ./deploy.sh)
rm -rf './.gs-pkg'
exit 0
__ARCHIVE_BELOW__'

cd "${SRCDIR}" || exit
(echo "$HEAD"; tar cfz - --owner=0 --group=0 "gs-netcat_"* "deploy.sh") >"${DSTDIR}/deploy-all.sh"
ls -al "${DSTDIR}/deploy-all.sh"
