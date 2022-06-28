#! /bin/bash

# Test deploy.sh in various docker images.
# To fetch binaries from live server us:
#     GS_LIVE=1 ./run_all.sh 
BASEDIR="$(cd "$(dirname "${0}")/../../../" || exit; pwd)"
GSPKGROOT="${BASEDIR}/packaging/gsnc-deploy-bin/"
STDIR="${GSPKGROOT}/selftest"

targets="ubi8 debian centos arch alpine rhel8 suse-tumbleweed"
[[ -n $* ]] && targets="$*"

errexit()
{
	echo >&2 "ERROR: $*"
	exit 255
}
docker_run()
{
	[[ -z $1 ]] && { echo >&2 "Parameters missing."; return; }
	[[ -f "${STDIR}/Dockerfile.${1}" ]] || { echo >&2 "Not found: Dockerfile.${1}"; return; }

	echo "Testing $1..."
	local dockername
	dockername="gs-selftest-${1}"

	docker run --rm -it "${dockername}" true || docker build -t "${dockername}" -f "${STDIR}/Dockerfile.${1}" . || { exit 255; }

	docker run --rm -v "${GSPKGROOT}:/gsocket-pkg" -e GS_LIVE="$GS_LIVE" -it "${dockername}" /gsocket-pkg/selftest/run.sh || { errexit "failed"; }
}

cp "${BASEDIR}/deploy/deploy.sh" "${GSPKGROOT}/selftest/deploy.sh"
for x in $targets; do
	docker_run $x
done
rm -f "${GSPKGROOT}/selftest/deploy.sh"

echo "SUCCESS."
