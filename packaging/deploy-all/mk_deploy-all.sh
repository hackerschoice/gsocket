#! /usr/bin/env bash

# Create deploy-all.sh:
# - Create a tar file containing all static binaries and deploy.sh
# - Create shell script with deploy-all_head.sh and append tar file to it.

BASEDIR="$(cd "$(dirname "${0}")/../../" || exit; pwd)"
source "${BASEDIR}/packaging/build_funcs"

targets="x86_64-alpine i386-alpine x86_64-debian aarch64-linux armv6l-linux x86_64-cygwin x86_64-freebsd x86_64-osx"
# targets="x86_64-alpine x86_64-osx"

PKG_DIR="gs-pkg"
FILE_DEPLOY_SH="../../deploy/deploy.sh"

errexit()
{
	[[ -z "$1" ]] || echo -e 1>&2 "ERROR: ${CR}$*${CN}"

	exit 255
}

check_file()
{
	[[ -f "$1" ]] || errexit "Not found: $1"
}

check_file deploy-all_head.sh
check_file "${FILE_DEPLOY_SH}"

rm -rf ./"$PKG_DIR"
mkdir "$PKG_DIR" 2>/dev/null

for osarch in $targets; do
	fn="gs-netcat_${osarch}.tar.gz"
	f="../gsnc-deploy-bin/${fn}"
	check_file "$f"
	ln -s "../${f}" "${PKG_DIR}/${fn}"
done
ln -s ../"${FILE_DEPLOY_SH}" "${PKG_DIR}/deploy.sh"

(cat deploy-all_head.sh; "${GTAR_BIN}" cfhz - --owner=0 --group=0 "$PKG_DIR") >deploy-all.sh
chmod 755 deploy-all.sh

ls -al deploy-all.sh
[[ -d "$PKG_DIR" ]] && rm -rf "${PKG_DIR}"
