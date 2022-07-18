#! /bin/bash

# Test-Compile & RUN release package on various VMs.
# EXAMPLE: RUN=1 NO_COMPILE=1 GSOCKET_HOST=gs1.thc.org ./test-compile.sh arch32

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
TOPDIR="$(cd "${BASEDIR}/../" || exit; pwd)"

CY="\033[1;33m" # yellow
CG="\033[1;32m" # green
CR="\033[1;31m" # red
CC="\033[1;36m" # cyan
CM="\033[1;35m" # magenta
CN="\033[0m"    # none

VER="$(grep AC_INIT "${TOPDIR}/configure.ac" | cut -f3 -d"[" | cut -f1 -d']')"

FILE="gsocket-${VER}.tar.gz"
DIR=$(echo "$FILE" | sed 's/\.tar\.gz//')

[[ -f "${TOPDIR}/$FILE" ]] || make dist
[[ -f "${TOPDIR}/$FILE" ]] || { echo >&2 "$FILE not found."; exit 255; }
echo "Using:"
(cd "${TOPDIR}" && ls -al "$FILE" && sha256sum "$FILE")

targets+=("osx")
targets+=("sid")
targets+=("cygwin")
targets+=("kali64")
targets+=("arch64")
targets+=("arch32")
targets+=("alpine64")
targets+=("debian" "ubuntu")
targets+=("centos" "linux32")
targets+=("fbsd" "bengal")
targets+=("rpi")
targets+=("solaris11" "solaris10")
targets+=("openwrt")

[[ -n $1 ]] && targets=("$@")

shellcheck "${TOPDIR}/tools/gs-sftp"
shellcheck "${TOPDIR}/tools/blitz"
shellcheck "${TOPDIR}/tools/gs-mount"
shellcheck "${TOPDIR}/tools/gs_funcs"
shellcheck "${TOPDIR}/tools/gsocket"
shellcheck "${TOPDIR}/deploy/deploy.sh"

if [[ -z $GSOCKET_DOMAIN ]] && [[ -z $GSOCKET_HOST ]]; then
	[[ -z $GSOCKET_IP ]] && GSOCKET_IP=192.168.1.16
	#GSOCKET_PORT=7351
	GSOCKET_IP=213.202.239.83
	# GSOCKET_IP=
fi

ENVPARAM="QUICK=y GSOCKET_PORT=${GSOCKET_PORT} GSOCKET_HOST=${GSOCKET_HOST} GSOCKET_IP=${GSOCKET_IP}"
ENVPARAM_CSH="setenv QUICK y; setenv GSOCKET_PORT ${GSOCKET_PORT}; setenv GSOCKET_IP ${GSOCKET_IP}; setenv GSOCKET_HOST ${GSOCKET_HOST};"

[[ -z $NO_COMPILE ]] && WITH_COMPILE=1

# Load configuration
[[ -f "${BASEDIR}/compile.conf" ]] && source "${BASEDIR}/compile.conf"

do_test()
{
	local target
	local REXEC_CMD
	local PREFIX
	local DST
	local ENV_run
	target="$1"

	COUNT=$((COUNT + 1))
	CSTR="${CR}[${COUNT}/${#targets[@]}]${CN}"

	REXEC_CMD=$(eval echo \$${target}_REXEC_CMD) 
	PREFIX=$(eval echo \$${target}_PREFIX)
	DST=$(eval echo \$${target}_DST) 
	PRE_EXEC=$(eval echo \$${target}_PRE_EXEC)
	COMPILE_EXEC=$(eval echo \$${target}_COMPILE_EXEC)
	RUN_EXEC=$(eval echo \$${target}_RUN_EXEC)
	ENV_conf=$(eval echo \$${target}_ENV)

	[[ -z $DST ]] && DST="."
	[[ -z $PRE_EXEC ]] && PRE_EXEC="true"
	[[ -z $ENV_conf ]] && ENV_run="${ENVPARAM}" || ENV_run="$ENV_conf"

	if [[ -n $PREFIX ]]; then
		if [[ $ENV_run =~ "setenv" ]]; then
			ENV_run+=" setenv GS_PREFIX ${PREFIX};"
		else
			ENV_run+=" GS_PREFIX=${PREFIX}"
		fi
	fi

	if [[ -n $WITH_COMPILE ]]; then
		echo -e "${CSTR} ${CG}Compiling ${CY}${target}${CN} [${REXEC_CMD}]"
		if [[ -n $COMPILE_EXEC ]]; then
			# HERE: Custom compile action (for openwrt)
			$REXEC_CMD "$COMPILE_EXEC" || { echo "Failed-3 ${*}"; exit 253; }
			echo "Done ${target}. [${COMPILE_EXEC}]"
			return
		fi

		if [[ -z "${PREFIX}" ]]; then
			COMPILE="cd ${DST}/$DIR && find . -type f -exec touch -r /etc/passwd {} \\; && ./configure --enable-tests && make clean all"
		else
			COMPILE="cd ${DST}/$DIR && find . -type f -exec touch -r /etc/passwd {} \\; && ./configure --prefix=${PREFIX} --enable-tests && make clean all install"
		fi
		# Must use two logins so we get color output (tty connected)
		(cat "${TOPDIR}/${FILE}" ) | $REXEC_CMD "$PRE_EXEC && (cd $DST; gunzip | tar xf -)" && \
			$REXEC_CMD "$COMPILE"

		[[ $? -eq 0 ]] || { echo "Failed ${target} [${REXEC_CMD}]"; exit 255; }
	fi


	if [[ -n "$RUN" ]]; then
		echo -e "${CSTR} ${CM}TESTING ${CY}${target}${CN} [${REXEC_CMD}]"
		# OpenWRT does not have a RUN test...
		if [[ -n $RUN_EXEC ]]; then
			$REXEC_CMD "$RUN_EXEC" || { echo "Failed-2 ${*}"; exit 254; }
		else
			$REXEC_CMD "cd ${DST}/${DIR}/tests/ && ${ENV_run} ./run_all_tests.sh" || { echo "Failed-2 ${*}"; exit 254; }
		fi
	fi
	echo "Done ${target}. [${REXEC_CMD}]"
}

for t in "${targets[@]}"; do
	do_test "${t}"
done
