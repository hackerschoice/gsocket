#! /bin/bash

# Test script against test-gsrn to test flaky TCP connections and SSL:
# The script creates gs-netcat traffic and then at random intervals kills
# the connection. The TCP stream to test-gsrn server is also configured to
# introduce packet loss.

# cut & paste friendly to set up packet loss on test-gsrn:
: <<'__END_COMMENT__'
DEV=wlan0
tc qdisc add dev ${DEV} root netem loss 1%
tc qdisc change dev ${DEV} root netem corrupt 2%
tc qdisc change dev ${DEV} root netem duplicate 1%
#tc qdisc change dev ${DEV} root netem delay 50ms reorder 25%
tc qdisc change dev ${DEV} root netem delay 500ms reorder 25%
__END_COMMENT__

CY="\033[1;33m" # yellow
CG="\033[1;32m" # green
CR="\033[1;31m" # red
CC="\033[1;36m" # cyan
CM="\033[1;35m" # magenta
CN="\033[0m"    # none

[[ "$GSOCKET_IP" = *192\.168* ]] || { echo >&2 "No testing GSRN set: export GSOCKET_IP=\"192.168.x.x\"."; exit 255; }
[[ -z $GSOCKET_ARGS ]] && {
	SECRET=$(../tools/gs-netcat -g)
	export GSOCKET_ARGS="-s $SECRET"
	echo "Start the GS listening process with:"
	echo "    GSOCKET_ARGS=\"-s $SECRET\" gs-netcat -l -e bash"
	echo "Press Return to continue..."
	read
}

# Wait until a process has termianted or kill it after SLEEP_WD seconds..
# waitkp <pid> [<seconds>]
waitkp()
{
	local x
	local sleep_wd

	sleep_wd=$2
	[[ -z $sleep_wd ]] && sleep_wd=10 # default is 10 seconds.

    x=0;
    rounds=`bc <<<"$sleep_wd / 0.1"`
    while :; do
            kill -0 $1 &>/dev/null
            if [ $? -ne 0 ]; then
                    # Break if process is not running.
                    return
            fi
            sleep 0.1
            x=$(($x + 1))
            if [ $x -gt $rounds ]; then
                    break;
            fi
    done

    echo -e "${CR}Killing hanging process $1....${CN}"
    kill -9 $1 &>/dev/null
}

run_timelimit()
{
	local sec_wait
	sec_wait=$1
	shift;
	sh -c "$*" >/dev/null &
	# sh -c "$*"  &
	echo Started pid ${!}
	waitkp ${!} $sec_wait
}

# run_timelimit 2 "sleep 5" 
# echo foobar
# exit

i=0
while :; do
	i=$((i+1))
	echo -e "${CY}-----$(date)-----${CN}"

	echo -e "${CG}Iteration #${i}.1${CN}"
	run_timelimit 10 '{ sleep 4; echo "dd bs=1k count=8 if=/dev/urandom | openssl base64; exit"; sleep 2;} | ../tools/gs-netcat'

	echo -e "${CG}Iteration #${i}.2${CN}"
	# Getting an odd 'line 38: 12345 Killed: 9  sh -c "$*" output here
	# is normal because we kill the 'sh -c' process (e.g. kills itself).
	# This will also send sigpipe to '| ../tools/gs-netcat'.
	run_timelimit 10 '{ echo "dd bs=1k count=8 if=/dev/urandom | openssl base64"; sleep 5; killall -9 gs-netcat;} | ../tools/gs-netcat'
	# run_timelimit 10 '{ echo "dd bs=1k count=8 if=/dev/urandom | openssl base64"; sleep 5; kill -9 $$;} | ../tools/gs-netcat'

	echo -e "${CG}Iteration #${i}.3${CN}"
	run_timelimit 10 '{ echo "(dd bs=1k count=111256 if=/dev/urandom | openssl base64 ) & sleep 1.1; exit"; sleep 8; killall -9 gs-netcat;} | ../tools/gs-netcat'
done


