#! /bin/bash

BASEDIR="$(cd "$(dirname "${0}")/../.." || exit; pwd)"
VER="$(grep AC_INIT "${BASEDIR}/configure.ac" | cut -f3 -d"[" | cut -f1 -d']')"

PKGDIR="${BASEDIR}/packaging"
SRCDIR="${BASEDIR}/packaging/build/gsocket-${VER}"
DEBDIR="${BASEDIR}/packaging/debian-deb"

if [[ ! -f "${SRCDIR}/configure.ac" ]]; then
	tar_orig="${BASEDIR}/gsocket-${VER}.tar.gz"
	[[ -f "$tar_orig" ]] && (cd "${BASEDIR}/packaging/build" && tar xfz "$tar_orig")
fi
[[ -d "$SRCDIR" ]] || { echo >&2 "Source not found: $SRCDIR or ${tar_orig}."; exit 255; }

dockername="gs-x86_64-debian-devel"
docker run --rm -it "${dockername}" true || (cd "${DEBDIR}" && docker build -t "${dockername}" . ) || { exit 255; }
docker run --rm  -v "${PKGDIR}:/gsocket-pkg" -v "${SRCDIR}:/gsocket-src" -v "${DEBDIR}:/gsocket-deb" -e VER=$VER -it "${dockername}" /gsocket-deb/build.sh || { exit 255; }
