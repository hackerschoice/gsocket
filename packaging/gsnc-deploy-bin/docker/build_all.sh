#! /bin/bash

# Build all binaries for gsocket.io/x deployment scripts
# Use docker.

BASEDIR="$(cd "$(dirname "${0}")/../../../" || exit; pwd)"
VER="$(grep AC_INIT "${BASEDIR}/configure.ac" | cut -f3 -d"[" | cut -f1 -d']')"
source "${BASEDIR}/packaging/build_funcs"

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
	echo "" >"${SRCDIR}/configure-parameters.txt"
	[[ -z $2 ]] || { echo "$2" >"${SRCDIR}/configure-parameters.txt"; }
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
	docker run --rm -it "${dockername}" true 2>/dev/null || ( cd docker && docker build -t "${dockername}" "${1}" ) || { exit 255; }
	
	[[ -f "${SRCDIR}/tools/gs-netcat" ]] && rm -f "${SRCDIR}/tools/gs-netcat"
	docker run --rm  -v "${SRCDIR}:/gsocket-src" -v "${GSNCROOT}:/gsocket-build" -it "${dockername}" /gsocket-build/build.sh || { exit 255; }
	(cd "${SRCDIR}/tools" && ${GTAR_BIN} cfz "${dsttar}" --mode=755 --owner=0 --group=0 gs-netcat)
	(cd "${dstdir}" && shasum "${filename}" && ls -al "${filename}")
}

cd "${BASEDIR}/packaging/gsnc-deploy-bin"
docker_pack armv6l-linux "--host=armv6l" && \
docker_pack aarch64-linux "--host=aarch64" && \
docker_pack mips64-alpine "--host=mips64" && \
docker_pack mips32-alpine "--host=mips32" && \
docker_pack x86_64-alpine && \
docker_pack i386-alpine && \
{ echo "SUCCESS"; exit 0; }

# USE ALPINE docker_pack x86_64-debian && \
exit 255
