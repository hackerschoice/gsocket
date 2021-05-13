#! /bin/bash

# Build all binaries for gsocket.io/x deployment scripts
# Use docker.

BASEDIR="$(cd "$(dirname "${0}")/../../../" || exit; pwd)"
VER="$(grep AC_INIT "$BASEDIR/configure.ac" | cut -f2 -d" " | cut -f1 -d')')"

SRCDIR="${BASEDIR}/packaging/build/gsocket-${VER}"
GSNCROOT="${BASEDIR}/packaging/gsnc-deploy-bin/docker"

if [[ ! -f "${SRCDIR}"/configure.ac ]]; then
	tar_orig="${BASEDIR}/gsocket-${VER}.tar.gz"
	[[ -f "$tar_orig" ]] && (cd "${BASEDIR}/packaging/build" && tar xfz "$tar_orig")
fi
[[ -d "$SRCDIR" ]] || { echo >&2 "Source not found: $SRCDIR or ${tar_orig}."; exit 255; }

docker_pack()
{
	[[ -z $1 ]] && { echo >&2 "Parameters missing."; return; }
	local dsttar
	local filename
	local dockername
	local dstdir
	filename="gs-netcat_${1}.tar.gz"
	dstdir="${GSNCROOT}/.."
	dsttar="${dstdir}/${filename}"
	dockername="gs-${1}"

	[[ -f "${dsttar}" ]] && { echo >&2 "${filename} exists. Skipping."; return; }
	rm -f "${dsttar}"
	# Create local docker container if it does not yet exist
	docker run --rm -it "${dockername}" true || docker build -t "${dockername}" "${1}" || { exit 255; }
	
	[[ -f "${SRCDIR}/tools/gs-netcat" ]] && rm -f "${SRCDIR}/tools/gs-netcat"
	docker run --rm  -v "${SRCDIR}:/gsocket-src" -v "${GSNCROOT}:/gsocket-build" -it "${dockername}" /gsocket-build/build.sh || { exit 255; }
	(cd "${SRCDIR}/tools" && tar cfz "${dsttar}" --uid 0 --gid 0 gs-netcat)
	(cd "${dstdir}" && shasum "${filename}" && ls -al "${filename}")
}

docker_pack x86_64-centos 
docker_pack x86_64-alpine 
docker_pack i386-debian
docker_pack x86_64-debian
# docker_pack x86_64-arch # NOT SUPPORTED. configure fails with "This script requires a shell more modern than all"