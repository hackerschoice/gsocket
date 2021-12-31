#! /usr/bin/env bash

# Extract deploy.sh and binary packages from _this script_

PKG_DIR="gs-pkg"

errexit()
{
	[[ -z "$1" ]] || echo -e 1>&2 "ERROR: ${CR}$*${CN}"

	exit 255
}

check_file()
{
	[[ -f "$1" ]] || errexit "Not found: $1"
}

check_file "$0"

lc=0
while read l; do
	lc=$(($lc + 1))
	[[ "$l" = "# ---END---" ]] && break
done <"$0"

[[ $lc -eq 0 ]] && errexit "Cant determine my own file size."

# Skip all lines until ---END--- and then untar binaries
(head -n"${lc}" >/dev/null; tar xfz -)<"$0" 

check_file "${PKG_DIR}/deploy.sh"
chmod 755 "${PKG_DIR}/deploy.sh"

(cd "${PKG_DIR}" && GS_USELOCAL=1 ./deploy.sh)
rm -rf ./"${PKG_DIR}"
exit 0
# Do not change the next line
# ---END---
