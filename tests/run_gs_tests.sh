#! /bin/bash

#export GSOCKET_IP=127.0.0.1
#export GSOCKET_PORT=31337

# Simulate bad network
# https://medium.com/@docler/network-issues-simulation-how-to-test-against-bad-network-conditions-b28f651d8a96

# DEV=wlan0
# tc qdisc add dev ${DEV} root netem loss 1%
# tc qdisc change dev ${DEV} root netem corrupt 2%
# tc qdisc change dev ${DEV} root netem duplicate 1%
# tc qdisc change dev ${DEV} root netem delay 50ms reorder 25%

# # delete all after use:
# tc qdisc del dev ${DEV} root

# depend on: md5sum, rsync, netstat, netcat, dd, ssh, sshd

CY="\033[1;33m" # yellow
CG="\033[1;32m" # green
CR="\033[1;31m" # red
CC="\033[1;36m" # cyan
CM="\033[1;35m" # magenta
CN="\033[0m"    # none

# Debian packaging: Force CWD to ./tests/
BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"
cd "$BASEDIR"

# Sleep for connection time (CT). On localhost this can be 0.1
SLEEP_CT=0.5

if [ x"$GSOCKET_IP" == "x127.0.0.1" ]; then
	SLEEP_CT=0.1
fi

if [[ -z $GS_PREFIX ]]; then
	# User binaries from built-directory
	GS_BINDIR="$(cd ${BASEDIR}/../tools || exit; pwd)"
else
	GS_BINDIR="${GS_PREFIX}/bin"
fi
export PATH=${GS_BINDIR}:/usr/local/bin:$PATH

echo -e "${CY}*** ${CM}$(gs-netcat -h 2>&1 | grep ^Version)${CY} ***${CN}"

# printf "#! /bin/bash\nexec nc\n" >gs_nc
SLEEP_WD=20	# Max seconds to wait for a process to finish receiving...
command -v md5 >/dev/null 2>&1 		&& MD5(){ md5 -q "${1}" 2>/dev/null;}
command -v md5sum >/dev/null 2>&1 	&& MD5() { md5sum "${1}" 2>/dev/null | cut -f1 -d' ';}
command -v rsync >/dev/null 2>&1 || { echo >&2 "rsync not installed. apt-get install rsync."; exit 255; }
command -v netstat >/dev/null 2>&1 && { IS_HAVE_NETSTAT=1; }
# Use traditional netcat that supports "netcat -nlp" for cross-platform comp.
# on CentOS there is only nmap's netcat as 'nc' but we are expecting 'netcat()'.
if [[ "$(nc --version 2>&1)" =~ Ncat ]]; then
	NC=nc
	NC_EOF_ARG=" " #not empty
	NC_LISTEN_ARG="-nlp"
else
	# Try traditional netcat first.
	if command -v netcat >/dev/null 2>&1; then
		NC=netcat
	else 
		if command -v nc >/dev/null 2>&1; then
			NC=nc #cygwin
		else
			echo >&2 "netcat not installed. apt-get install netcat."; exit 255;
		fi
	fi
fi

# Different OSes use different netcats:
if [[ -z "$NC_EOF_ARG" ]]; then
	# HERE: Not Ncat
	if [[ $($NC --help 2>&1) =~ "close connection on EOF" ]]; then
		NC_EOF_ARG="-c"
	elif [[ $($NC --help 2>&1) =~ "w timeout" ]]; then
		NC_EOF_ARG="-w2" # cygwin needs at least -w2 (-w1 fails at times)
	elif [[ $($NC -h 2>&1) =~ "quit after EOF on" ]]; then
		NC_EOF_ARG="-q1"
	elif [[ -f /bin/busybox ]]; then
		NC_EOF_ARG="-w5"
	else
		NC_EOF_ARG="-q1"
	fi
fi

if [[ -z "$NC_LISTEN_ARG" ]]; then
	if [[ $($NC --help 2>&1) =~ "source_port" ]]; then
		# apple default : usage: nc [-46AacCDdEFhklMnOortUuvz] [-K tc] [-b boundif] [-i interval] [-p source_port]
		# fbsd default  : [-P proxy_username] [-p source_port] [-s source] [-T ToS]
		# cygwin default: [-P proxy_username] [-p source_port] [-s source] [-T ToS]
		NC_LISTEN_ARG="-nl"
	else
		NC_LISTEN_ARG="-nlp"
	fi
fi

# Find out how to get file size
fsize() { stat -c%s "$1" 2>/dev/null || echo 0;}
stat -f%z /etc/hosts &>/dev/null && fsize() { stat -f%z "$1" 2>/dev/null || echo 0;}

export NC
export NC_EOF_ARG
export NC_LISTEN_ARG
export NC_LISTEN="${NC} ${NC_LISTEN_ARG}"
export NC_LISTEN_EOF="${NC} ${NC_LISTEN_ARG} ${NC_EOF_ARG}"

sleep 0.1 &>/dev/null || { echo >&2 "sleep not accepting 0.1. PATH set correct?"; exit 255; }
OK="......[\033[1;32mOK\033[0m]"
FAIL="[\033[1;31mFAILED\033[0m]"
SKIP="[\033[1;33mskipping\033[0m]"
ECHO="echo -e"

if [[ -n "$IS_HAVE_NETSTAT" ]]; then
	NETSTATTCP(){ netstat -ant;}
	[[ "$OSTYPE" == *"solaris"* ]] && NETSTATTCP(){ netstat -an -f inet; }
	[[ "$OSTYPE" == *"BSD"* ]] && NETSTATTCP(){ netstat -an -f inet; }
else
	echo >&2 "***** WARNING: netstat not found. Attempting anyway... *****"
fi

tests+=("1.1")
tests+=("2.1" "2.2")
tests+=("3.1")
tests+=("4.1" "4.2")
tests+=("5.1" "5.2" "5.3" "5.4")
# tests+=("5.5")	# cleartext
tests+=("6.1" "6.2" "6.3" "6.4" "6.5" "6.6")	# gs-netcat
# tests+=("6.7")	# cleartext
tests+=("6.8")		# TOR
tests+=("7.1" "7.2" "7.3" "7.4")
tests+=("8.1" "8.2" "8.3")
tests+=("9.1" "9.2" "9.3" "9.4")
tests+=("10.1")         # blitz
tests+=("10.2" "10.3")  # gs-sftp, gs-mount (uchroot)
tests+=("10.4")		# gs-mount
tests+=("10.5")		# gsocket nc
tests+=("10.5.1")	# gsocket nc
tests+=("10.5.2")	# gsocket nc
tests+=("10.6")		# gsocket socat
tests+=("10.7")		# gsocket ssh

[[ -n $1 ]] && tests=("$@")

mk_dummy()
{
        # [ -f "$1" ] || dd bs=1024 count=$2 if=/dev/zero | tr '\000' '\101' >"$1" 2>/dev/null
        [ -f "$1" ] || dd bs=1024 count=$2 if=/dev/urandom of="$1" 2>/dev/null
}
mk_dummy test1k.dat 1
mk_dummy test4k.dat 4
mk_dummy test50k.dat 50
mk_dummy test1M.dat 1024
mk_dummy test50Mx.dat 51200
if [[ -n "$QUICK" ]]; then
	cp test50k.dat test50M.dat
else
	cp test50Mx.dat test50M.dat
fi
echo "Fubar" >>test50M.dat	# Make it an odd length
MD50MB="$(MD5 test50M.dat)"
MD1MB="$(MD5 test1M.dat)"
MDHELLOW="$(echo "Hello World" | MD5 /dev/stdin)"

test_start()
{
	rm -f client_out.dat server_out.dat server_err.txt client_err.txt server[123]_out.dat client[12]_out.dat server[123]_err.txt client[12]_err.txt nc[123]_out.dat nc[123]_err.txt
	[[ x"$1" != x ]] && $ECHO $*
	# [[ -s id_sec.txt ]] || new_id
	# Each test needs a new gsocket-secret or GSRN reports BAD-TOKEN.
	new_id
}

fail()
{
	$ECHO "${FAIL}"-$*
	exit 255
}

skip()
{
	$ECHO "${SKIP}" $*
}

# code file1 file2 pid-to-kill
md5fail()
{
	[[ -n $4 ]] && [[ "$(MD5 ${2})" != "$(MD5 ${3})" ]] && { kill -9 $4 &>/dev/null; fail $1; }
	[[ "$(MD5 ${2})" != "$(MD5 ${3})" ]] && fail $1
}

# Wait until a process has termianted or kill it after SLEEP_WD seconds..
waitkp()
{
	local x
	local rounds
	x=0
	rounds=$((SLEEP_WD * 10))
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

	echo "Killing hanging process...."
	kill -9 $1 &>/dev/null
	exit 255
}

waitk()
{
	for p in $@; do
		waitkp $p
	done
}

# waitkpf <pid> <file>
# Kill if file doesnt change for SLEEP_WD seconds or when PID 
# has finished.
waitkpf()
{
	local x
	local rounds
	local fz
	local fz_old
	x=0
	fsz_old=0
	rounds=$(($SLEEP_WD * 10))
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
		fz="$(fsize "$2")"
		if [[ $fz -ne $fz_old ]]; then
			fz_old=$fz
			x=0
		fi
	done

	echo "Killing hanging process....($2 did not change size for to long ($fz)"
	kill -9 $1 &>/dev/null
	exit 255
}

# Wait for 2 files to become identical...
waitf()
{
	x=0;
	rounds=$(($SLEEP_WD * 10))
	while :; do
		if [ "$(MD5 $1)" == "$(MD5 $2)" ]; then
			return
		fi
		sleep 0.1
		x=$(($x + 1))
		if [ $x -gt $rounds ]; then
			break;
		fi
	done	
	echo "Oops. files not identical...."	
}

# Wait for file to match has
waitfhash()
{
	x=0;
	rounds=$(($SLEEP_WD * 10))
	while :; do
		if [ "$(MD5 $1)" == "$2" ]; then
			return
		fi
		sleep 0.1
		x=$(($x + 1))
		if [ $x -gt $rounds ]; then
			break;
		fi
	done	
	echo "Oops. files not identical...."	
}

waittcp()
{
	# If we do not have netstat then sleep in the hope that port opens and then
	# return.
	[[ -z "$IS_HAVE_NETSTAT" ]] && { sleep 1; return; }
	x=0;
	rounds=$(($SLEEP_WD * 10))
	while :; do
		NETSTATTCP 2>/dev/null | grep LISTEN | grep "$1" &>/dev/null
		if [ $? -eq 0 ]; then
			return
		fi
		sleep 0.1
		x=$(($x + 1))
		if [ $x -gt $rounds ]; then
			break;
		fi
	done
	echo "Oops. TCP $1 not listening...."
}

sleep_ct()
{
	sleep $SLEEP_CT
}

new_id()
{
	# Create a random secret for all tests
	../tools/gs-helloworld -g 2>/dev/null >id_sec.txt
}

# killall -9 gs-helloworld gs-pipe gs-full-pipe gs-netcat &>/dev/null
# [[ -f id_sec.txt ]] || new_id

if [[ " ${tests[*]} " =~ ' 1.1 ' ]]; then
### 1 - Hello World
test_start -n "Running: Hello World #1.1 ................................"
GSPID="$(sh -c '../tools/gs-helloworld -k id_sec.txt -l 2>server_err.txt >server_out.dat & echo ${!}')"
# sleep 0.5 required or otherwise kernel will send both strings in single
# tcp and that would result in a single read() call on other side.
sleep_ct && (echo "Hello World"; sleep 1; echo "That's the end") | ../tools/gs-helloworld -w -k id_sec.txt 2>client_err.txt >client_out.dat
waitk $GSPID
if [ "$(MD5 client_out.dat)" != "628eca04c4cb6c8f539381be1c5cd325" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 2.1 ' ]]; then
### 2 - Pipe
# Normal (server listening, client connecting)
test_start -n "Running: pipe #2.1 ......................................."
GSPID="$(sh -c '../tools/gs-pipe -k id_sec.txt -l 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct && ../tools/gs-pipe -k id_sec.txt <test50k.dat 2>client_err.txt >client_out.dat
waitk $GSPID
if [ "$(MD5 test50k.dat)" != "$(MD5 server_out.dat)" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 2.2 ' ]]; then
### Waiting client test
test_start -n "Running: pipe #2.2 (waiting for server)..................."
GSPID="$(sh -c '../tools/gs-pipe -k id_sec.txt -w <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct && ../tools/gs-pipe -k id_sec.txt -l 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$(MD5 test50k.dat)" != "$(MD5 server_out.dat)" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 3.1 ' ]]; then
### Impersonate 'listen'
test_start -n "Running: pipe #3.1 (auth token)..........................."
GS1PID="$(sh -c '../tools/gs-pipe -k id_sec.txt -l -a player-alice 2>server1_err.txt >server1_out.dat & echo ${!}')"
GS2PID="$(sh -c '../tools/gs-pipe -k id_sec.txt -l -a player-alice 2>server2_err.txt >server2_out.dat & echo ${!}')"
# Next server should not be allowed to listen (wrong -a key)
sleep_ct
../tools/gs-pipe -k id_sec.txt -l -a player-mallory 2>server3_err.txt >server3_out.dat
RET=$?
if [ $RET -ne 255 ]; then fail 1; fi
# Here: Two servers are still running...
../tools/gs-pipe -k id_sec.txt <test50k.dat 2>client_err.txt >client_out.dat
../tools/gs-pipe -k id_sec.txt <test50k.dat 2>client_err.txt >client_out.dat
waitk $GS1PID $GS2PID &>/dev/null
if [ "$(MD5 test50k.dat)" != "$(MD5 server1_out.dat)" ]; then fail 2; fi
if [ "$(MD5 test50k.dat)" != "$(MD5 server2_out.dat)" ]; then fail 3; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 4.1 ' ]]; then
### Client to become a server if no server is listening
test_start -n "Running: pipe #4.1 (become server if possible)............"
GSPID="$(sh -c '../tools/gs-pipe -k id_sec.txt -A <test1k.dat 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct
../tools/gs-pipe -k id_sec.txt -A <test50k.dat 2>client_err.txt >client_out.dat
waitk $GSPID
FC=0
[[ "$(MD5 test50k.dat)" != "$(MD5 server_out.dat)" ]] && FC=$((FX+1))
[[ "$(MD5 test1k.dat)" != "$(MD5 client_out.dat)" ]] && FC=$((FX+1))
[[ "$FC" != 1 ]] && fail 1
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 4.2 ' ]]; then
# Client already waiting. 2nd client to become server (if no server available)
test_start -n "Running: pipe #4.2 (..while client waiting)..............."
GSPID="$(sh -c '../tools/gs-pipe -k id_sec.txt -w <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
../tools/gs-pipe -k id_sec.txt -A 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$(MD5 test50k.dat)" != "$(MD5 server_out.dat)" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 5.1 ' ]]; then
test_start -n "Running: full-pipe #5.1..................................."
GSPID="$(sh -c '../tools/gs-full-pipe -k id_sec.txt -A <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
../tools/gs-full-pipe -k id_sec.txt -A <test50k.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$(MD5 test50k.dat)" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test50k.dat)" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 5.2 ' ]]; then
test_start -n "Running: full-pipe #5.2 (50MB)............................"
GSPID="$(sh -c '../tools/gs-full-pipe -k id_sec.txt -A <test50M.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
../tools/gs-full-pipe -k id_sec.txt -A <test50M.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$MD50MB" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$MD50MB" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 5.3 ' ]]; then
test_start -n "Running: full-pipe #5.3 (assym sizes, large server)......."
GSPID="$(sh -c '../tools/gs-full-pipe -k id_sec.txt -A <test1M.dat 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct
sleep 1
../tools/gs-full-pipe -A -k id_sec.txt <test50k.dat 2>client_err.txt >client_out.dat
waitk $GSPID &>/dev/null
# if [ "$MD50MB" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test1M.dat)" != "$(MD5 client_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test50k.dat)" != "$(MD5 server_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 5.4 ' ]]; then
test_start -n "Running: full-pipe #5.4 (assym sizes, small server)......."
GSPID="$(sh -c '../tools/gs-full-pipe -k id_sec.txt -A <test50k.dat 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct
sleep 1
../tools/gs-full-pipe -A -k id_sec.txt <test1M.dat 2>client_err.txt >client_out.dat
waitk $GSPID &>/dev/null
# if [ "$MD50MB" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test1M.dat)" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test50k.dat)" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 5.5 ' ]]; then
test_start -n "Running: full-pipe #5.5 (assymetric sizes, clear)........."
GSPID="$(sh -c '../tools/gs-full-pipe -k id_sec.txt -AC <test1M.dat 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct
../tools/gs-full-pipe -k id_sec.txt -AC <test4k.dat 2>client_err.txt >client_out.dat
waitk $GSPID
if [ "$MD1MB" != "$(MD5 client_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test4k.dat)" != "$(MD5 server_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 6.1 ' ]]; then
test_start -n "Running: netcat #6.1 (stdin, 1MB)........................."
GSPID="$(sh -c '../tools/gs-netcat -k id_sec.txt -w <test1M.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
../tools/gs-netcat -k id_sec.txt -l <test1M.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$MD1MB" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$MD1MB" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 6.2 ' ]]; then
test_start -n "Running: netcat #6.2 (stdin, assymetric sizes)............"
GSPID="$(sh -c '../tools/gs-netcat -k id_sec.txt -w <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
../tools/gs-netcat -k id_sec.txt -l <test1M.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$MD1MB" != "$(MD5 client_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test50k.dat)" != "$(MD5 server_out.dat)" ]; then fail 2; fi
# if [ "$MD1MB" != "$(MD5 server_out.dat)" ]; then fail 1; fi
# if [ "$(MD5 test50k.dat)" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 6.3 ' ]]; then
test_start -n "Running: netcat #6.3 (stdin, assym sizes, kill client)...."
GSPID1="$(sh -c '(cat test4k.dat; sleep 30) | ../tools/gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test1k.dat; sleep 30) | ../tools/gs-netcat -k id_sec.txt -l 2>server_err.txt >server_out.dat & echo ${!}')"
# sleep_ct
waitf test4k.dat server_out.dat
waitf test1k.dat client_out.dat
kill -9 $GSPID1 &>/dev/null
waitk $GSPID2
if [ "$(MD5 test4k.dat)" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test1k.dat)" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 6.4 ' ]]; then
test_start -n "Running: netcat #6.4 (stdin, assym sizes, kill server)...."
GSPID1="$(sh -c '(cat test4k.dat; sleep 30) | ../tools/gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test1k.dat; sleep 30) | ../tools/gs-netcat -k id_sec.txt -l 2>server_err.txt >server_out.dat & echo ${!}')"
waitf test4k.dat server_out.dat
waitf test1k.dat client_out.dat
kill -9 $GSPID2 &>/dev/null
waitk $GSPID1
if [ "$(MD5 test4k.dat)" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test1k.dat)" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 6.5 ' ]]; then
test_start -n "Running: netcat #6.5 (/dev/null C2S)......................"
GSPID="$(sh -c '../tools/gs-netcat -k id_sec.txt -w </dev/null 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
../tools/gs-netcat -k id_sec.txt -l <test4k.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ -s server_out.dat ]; then fail 1; fi
if [ "$(MD5 test4k.dat)" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 6.6 ' ]]; then
test_start -n "Running: netcat #6.6 (/dev/null S2C)......................"
GSPID="$(sh -c '../tools/gs-netcat -k id_sec.txt -w <test4k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
../tools/gs-netcat -k id_sec.txt -l </dev/null 2>server_err.txt >server_out.dat
waitk $GSPID
if [ -s client_out.dat ]; then fail 1; fi
if [ "$(MD5 test4k.dat)" != "$(MD5 server_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 6.7 ' ]]; then
test_start -n "Running: netcat #6.7 (stdin, assymetric sizes, clear)....."
GSPID="$(sh -c '../tools/gs-netcat -k id_sec.txt -wC <test1M.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
../tools/gs-netcat -k id_sec.txt -lC <test50k.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$MD1MB" != "$(MD5 server_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test50k.dat)" != "$(MD5 client_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 6.8 ' ]]; then
test_start -n "Running: netcat #6.8 (stdin, assymetric sizes, TOR)......."
if [[ "$GSOCKET_IP" =~ 192\.168\. ]]; then
	skip "$GSOCKET_IP"
elif [[ -z "$IS_HAVE_NETSTAT" ]]; then
	skip "(no netstat)"
elif ! NETSTATTCP 2>/dev/null | grep LISTEN | grep 9050 &>/dev/null; then
	skip "(no TOR)"
else
	GSPID="$(sh -c '../tools/gs-netcat -k id_sec.txt -wT <test4k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
	sleep_ct
	../tools/gs-netcat -k id_sec.txt -l <test50k.dat 2>server_err.txt >server_out.dat
	waitk $GSPID
	if [ "$(MD5 test4k.dat)" != "$(MD5 server_out.dat)" ]; then fail 1; fi
	if [ "$(MD5 test50k.dat)" != "$(MD5 client_out.dat)" ]; then fail 2; fi
	$ECHO "${OK}"
fi
fi

if [[ " ${tests[*]} " =~ ' 7.1 ' ]]; then
test_start -n "Running: netcat #7.1 (cmd, multi connect)................."
GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -l -e "echo Hello World && sleep 1" 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c '../tools/gs-netcat -k id_sec.txt -w </dev/null 2>client2_err.txt >client2_out.dat & echo ${!}')"
GSPID3="$(sh -c '../tools/gs-netcat -k id_sec.txt -w </dev/null 2>client3_err.txt >client3_out.dat & echo ${!}')"
../tools//gs-netcat -k id_sec.txt -w </dev/null 2>client_err.txt >client_out.dat
waitk $GSPID2 $GSPID3
kill -9 $GSPID1	&>/dev/null
if [ "${MDHELLOW}" != "$(MD5 client_out.dat)" ]; then fail 1; fi
if [ "${MDHELLOW}" != "$(MD5 client2_out.dat)" ]; then fail 2; fi
if [ "${MDHELLOW}" != "$(MD5 client3_out.dat)" ]; then fail 3; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 7.2 ' ]]; then
test_start -n "Running: netcat #7.2 (shell, exit)........................"
GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -l -e /bin/sh 2>server_err.txt >server_out.dat & echo ${!}')"
echo "date; echo Hello World; exit" | ../tools/gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat
sleep_ct
kill $GSPID1
if [ "${MDHELLOW}" != "$(tail -1 client_out.dat | MD5 /dev/stdin)" ]; then fail 1; fi
$ECHO "${OK}"
fi

# FreeBSD sends ansi-request to determine screen size. Wait for it to timeout and
# then send our command string.
XCMD="printf \"date && echo Hello World && exit\n\""
if [[ "$OSTYPE" == *"BSD"* ]]; then
	XCMD="sleep 3; ${XCMD}"
fi

if [[ " ${tests[*]} " =~ ' 7.3 ' ]]; then
test_start -n "Running: netcat #7.3 (pty shell, exit)...................."
GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -l -i 2>server_err.txt >server_out.dat & echo ${!}')"
# Can not start Client with -i because it's not a tty. Must 'fake' the terminal response.
sh -c "$XCMD" | ../tools/gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat
# (printf "date; echo Hello World; exit\n") | ../tools/gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat
sleep_ct
kill $GSPID1 
tail -2 client_out.dat | grep 'Hello World' &>/dev/null
if [ $? -ne 0 ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 7.4 ' ]]; then
test_start -n "Running: netcat #7.4 (multi pty shell, exit).............."
GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -l -i 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2=$(sh -c "($XCMD) | ../tools/gs-netcat -k id_sec.txt -w 2>client1_err.txt >client1_out.dat & echo \${!}")
GSPID3=$(sh -c "($XCMD) | ../tools/gs-netcat -k id_sec.txt -w 2>client2_err.txt >client2_out.dat & echo \${!}")
GSPID4=$(sh -c "($XCMD) | ../tools/gs-netcat -k id_sec.txt -w 2>client3_err.txt >client3_out.dat & echo \${!}")
waitk $GSPID2 $GSPID3 $GSPID4
kill $GSPID1
if [ x"$(tail -2 client1_out.dat | grep 'Hello World')" == x ]; then fail 1; fi
if [ x"$(tail -2 client2_out.dat | grep 'Hello World')" == x ]; then fail 2; fi
if [ x"$(tail -2 client3_out.dat | grep 'Hello World')" == x ]; then fail 3; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 8.1 ' ]]; then
test_start -n "Running: netcat #8.1 (port forward server side)..........."
GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -l -d 127.0.0.1 -p 12345 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c '(sleep 10) | $NC_LISTEN 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
waittcp 12345
GSPID3="$(sh -c '../tools/gs-netcat -k id_sec.txt -w <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
waitf test50k.dat nc1_out.dat
kill -9 $GSPID1 $GSPID2 $GSPID3 &>/dev/null
if [ "$(MD5 test50k.dat)" != "$(MD5 nc1_out.dat)" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 8.2 ' ]]; then
# nc -> Port 12344 -> GS-NET -> Port 12345 -> nc -ln
test_start -n "Running: netcat #8.2 (port forward both sides)............"
GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -l -d 127.0.0.1 -p 12345 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c '(sleep 1) | $NC_LISTEN 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
GSPID3="$(sh -c '../tools/gs-netcat -k id_sec.txt -w -p 12344 2>server2_err.txt >server2_out.dat & echo ${!}')"
waittcp 12344
waittcp 12345
GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | $NC -vn 127.0.0.1 12344 >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
waitf test50k.dat nc1_out.dat
kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
if [ "$(MD5 test50k.dat)" != "$(MD5 nc1_out.dat)" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 8.3 ' ]]; then
# nc -> Port 12344 -> GS-NET -> Port 12345 -> nc -ln
# Bi-Directional
test_start -n "Running: netcat #8.3 (port forward both sides, bi-dir)...."
GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -l -d 127.0.0.1 -p 12345 2>server1_err.txt >server1_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test4k.dat; sleep 15) | $NC_LISTEN 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
GSPID3="$(sh -c '../tools/gs-netcat -k id_sec.txt -w -p 12344 2>client_err.txt >client_out.dat & echo ${!}')"
waittcp 12344
waittcp 12345
GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | $NC -vn 127.0.0.1 12344 >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
waitf test50k.dat nc1_out.dat
waitf test4k.dat nc2_out.dat
kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
if [ "$(MD5 test50k.dat)" != "$(MD5 nc1_out.dat)" ]; then fail 1; fi
if [ "$(MD5 test4k.dat)" != "$(MD5 nc2_out.dat)" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 9.1 ' ]]; then
# SOCKS test socat -> port 1085 -> GS-NET -> Port 12345 -> nc -ln
test_start -n "Running: netcat #9.1 (socat/socks5)......................."
socat -h 2>/dev/null | grep socks5 &>/dev/null
if [ $? -ne 0 ]; then
	skip "(no socat2)"
else
	GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -lS 2>server1_err.txt >server1_out.dat & echo ${!}')"
	GSPID2="$(sh -c '(cat test4k.dat; sleep 15) | $NC_LISTEN 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
	GSPID3="$(sh -c '../tools/gs-netcat -k id_sec.txt -w -p 1085 2>client_err.txt >client_out.dat & echo ${!}')"
	waittcp 1085
	waittcp 12345
	GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | socat -  "SOCKS5:localhost:12345 | TCP:127.1:1085" >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
	waitf test50k.dat nc1_out.dat
	waitf test4k.dat nc2_out.dat
	kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
	if [ "$(MD5 test50k.dat)" != "$(MD5 nc1_out.dat)" ]; then fail 1; fi
	if [ "$(MD5 test4k.dat)" != "$(MD5 nc2_out.dat)" ]; then fail 2; fi
	$ECHO "${OK}"
	fi
fi

if [[ " ${tests[*]} " =~ ' 9.2 ' ]]; then
# SOCKS test socat -> port 1085 -> GS-NET -> Port 12345 -> nc -ln
test_start -n "Running: netcat #9.2 (socat/socks4)......................."
socat -h 2>/dev/null | grep socks4 &>/dev/null
if [ $? -ne 0 ]; then
	skip "(no socat)"
else
	GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -lS 2>server1_err.txt >server1_out.dat & echo ${!}')"
	GSPID2="$(sh -c '(cat test4k.dat; sleep 15) | $NC_LISTEN 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
	GSPID3="$(sh -c '../tools/gs-netcat -k id_sec.txt -w -p 1085 2>client_err.txt >client_out.dat & echo ${!}')"
	waittcp 1085
	waittcp 12345
	GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | socat -  "SOCKS4:127.0.0.1:127.0.0.1:12345,socksport=1085" >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
	waitf test50k.dat nc1_out.dat
	waitf test4k.dat nc2_out.dat
	kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
	if [ "$(MD5 test50k.dat)" != "$(MD5 nc1_out.dat)" ]; then fail 1; fi
	if [ "$(MD5 test4k.dat)" != "$(MD5 nc2_out.dat)" ]; then fail 2; fi
	$ECHO "${OK}"
	fi
fi

if [[ " ${tests[*]} " =~ ' 9.3 ' ]]; then
# SOCKS test socat -> port 1085 -> GS-NET -> Port 12345 -> nc -ln
test_start -n "Running: netcat #9.3 (socat/socks4a)......................"
socat -h 2>/dev/null | grep socks4 &>/dev/null
if [ $? -ne 0 ]; then
	skip "(no socat)"
else
	GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -lS 2>server1_err.txt >server1_out.dat & echo ${!}')"
	GSPID2="$(sh -c '(cat test4k.dat; sleep 15) | $NC_LISTEN 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
	GSPID3="$(sh -c '../tools/gs-netcat -k id_sec.txt -w -p 1085 2>client_err.txt >client_out.dat & echo ${!}')"
	waittcp 1085
	waittcp 12345
	GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | socat -  "SOCKS4a:127.0.0.1:127.0.0.1:12345,socksport=1085" >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
	waitf test50k.dat nc1_out.dat
	waitf test4k.dat nc2_out.dat
	kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
	if [ "$(MD5 test50k.dat)" != "$(MD5 nc1_out.dat)" ]; then fail 1; fi
	if [ "$(MD5 test4k.dat)" != "$(MD5 nc2_out.dat)" ]; then fail 2; fi
	$ECHO "${OK}"
	fi
fi

if [[ " ${tests[*]} " =~ ' 9.4 ' ]]; then
# SOCKS test with cUrl
test_start -n "Running: netcat #9.4 (curl/socks5, multi)................."
curl --help all 2>/dev/null | grep socks5-hostname &>/dev/null
if [ $? -ne 0 ]; then
	skip "(no curl)"
elif [[ "$(uname -a)" == *"GNU hurd"* ]]; then
	# on GNU hurd curl & https to localhost sometimes thows a 'bad record mac' error.
	# The cause is unknown. Works fine when gs-netcat runs on GNU hurd but curl
	# from another host is used.
	skip "(bad curl)"
else
	GSPID1="$(sh -c '../tools/gs-netcat -k id_sec.txt -lS 2>server_err.txt >server_out.dat & echo ${!}')"
	GSPID3="$(sh -c '../tools/gs-netcat -k id_sec.txt -w -p 1085 2>client_err.txt >client_out.dat & echo ${!}')"
	waittcp 1085
	touch testmp3.dat testmp3-2.dat
	GSPID4="$(sh -c 'curl --socks5-hostname 127.0.0.1:1085 --output testmp3.dat https://raw.githubusercontent.com/hackerschoice/thc-art/master/deep-phreakin.mp3 >client1_out.dat 2>client1_err.txt & echo ${!}')"
	GSPID5="$(sh -c 'curl --socks5-hostname 127.0.0.1:1085 --output testmp3-2.dat https://raw.githubusercontent.com/hackerschoice/thc-art/master/deep-phreakin.mp3 >client2_out.dat 2>client2_err.txt & echo ${!}')"
	# waitk $GSPID4 $GSPID5
	waitkpf $GSPID4 testmp3.dat
	waitkpf $GSPID5 testmp3-2.dat
	kill -9 $GSPID1 $GSPID3 &>/dev/null 
	if [ "$(MD5 testmp3.dat)" != "171a9952951484d020ce1bef52b9eef5" ]; then fail 1; fi
	if [ "$(MD5 testmp3-2.dat)" != "171a9952951484d020ce1bef52b9eef5" ]; then fail 2; fi
	$ECHO "${OK}"
	fi
fi

if [[ " ${tests[*]} " =~ ' 10.1 ' ]]; then
test_start -n "Running: blitz #10.1 ....................................."
rm -rf test_server test_client
mkdir -p test_server test_client/foo/bar test_client/empty
if ! mkfifo test_client/fifo.io &>/dev/null; then
	skip "(mkfifo)" # likely on a VMBOX shared drive
else
	cp test4k.dat test_client/foo/bar/test4k.dat
	cp test1k.dat test_client/foo/bar/test1k.dat
	cp test1k.dat test_client/test1k.dat
	ln -s foo/bar/test4k.dat test_client/test4k.dat
	ln -s /etc/hosts test_client/etc-hosts
	ln -s /dev/zero test_client/zero
	GSPID1="$(sh -c 'blitz -k id_sec.txt -w -o "RSOPT=--bwlimit=100 -v" test_client/./ 2>client1_err.txt >client1_out.dat & echo ${!}')"
	cd test_server
	GSPID2="$(sh -c 'blitz -k ../id_sec.txt -l 2>../server1_err.txt >../server1_out.dat & echo ${!}')"
	cd ..
	waitk $GSPID1
	kill $GSPID2
	(cd test_client; find . -type f | while read x; do md5fail 1 ../test_server/${x} ${x}; done)
	md5fail 2 test_server/test4k.dat test4k.dat
	[[ -e test_server/fifo.io ]] && fail 3
	[[ -e test_server/zero ]] && fail 4
	[[ -e test_server/etc-hosts ]] && fail 5
	[[ -L test_server/test4k.dat ]] || fail 6
	[[ -d test_server/empty ]] || fail 7
	rm -rf test_server test_client
	$ECHO "${OK}"
	fi
fi

if [[ " ${tests[*]} " =~ ' 10.2 ' ]]; then
test_start -n "Running: blitz #10.2 (stdin).............................."
rm -rf test_client
mkdir -p test_client
GSPID1="$(sh -c '(echo test1k.dat; echo test4k.dat) | blitz -k id_sec.txt -w -o "RSOPT=--bwlimit=100 -v" -f - 2>client1_err.txt >client1_out.dat & echo ${!}')"
cd test_client
GSPID2="$(sh -c 'blitz -k ../id_sec.txt -l 2>../server1_err.txt >../server1_out.dat & echo ${!}')"
cd ..
waitk $GSPID1
kill $GSPID2
md5fail 1 test1k.dat test_client/test1k.dat
md5fail 2 test4k.dat test_client/test4k.dat
rm -rf test_client
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 10.3' ]]; then
test_start -n "Running: gs-sftp #10.3 ..................................."
rm -rf test_client
mkdir -p test_client
GSPID1="$(bash -c '(echo -en "lcd test_client\nget test4k.dat\nlcd ..\ncd test_client\nput test1k.dat\nls\nquit\n") | gs-sftp -k id_sec.txt -w 2>client1_err.txt >client1_out.dat & echo ${!}')"
GSPID2="$(sh -c 'gs-sftp -k id_sec.txt -l 2>server1_err.txt >server1_out.dat & echo ${!}')"
waitk $GSPID1
kill $GSPID2
md5fail 1 test1k.dat test_client/test1k.dat
md5fail 2 test4k.dat test_client/test4k.dat
# rm -rf test_client
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 10.4 ' ]]; then
test_start -n "Running: gs-mount #10.4 .................................."
command -v sshfs  >/dev/null 2>&1
if [ $? -ne 0 ]; then
	skip "(no sshfs)"
elif [[ "$OSTYPE" == *"darwin"* ]]; then
	# osxfuse and macosfuse are both broken now
	# macosfuse hangs the host. force-unmount not working. Not recoverable. reboot needed.
	skip "OSX fuse-broken"
else	
	rm -rf test_client &>/dev/null
	rmdir test_mnt &>/dev/null
	mkdir -p test_client test_mnt &>/dev/null
	cp test1k.dat test4k.dat test_client
	GSPID1="$(sh -c 'gs-mount -k id_sec.txt -w test_mnt 2>client1_err.txt >client1_out.dat & echo ${!}')"
	GSPID2="$(sh -c 'cd test_client; gs-mount -k ../id_sec.txt -l 2>../server1_err.txt >../server1_out.dat & echo ${!}')"
	waitk $GSPID1
	if grep forbidden client1_err.txt &>/dev/null; then
		skip "(forbidden)" # VMBox drive?
	else
		md5fail 1 test_mnt/test1k.dat test_client/test1k.dat $GSPID2
		md5fail 2 test_mnt/test4k.dat test_client/test4k.dat $GSPID2
		if command -v fusermount >/dev/null 2>&1; then
			fusermount -zu test_mnt
		else
			# archLinux -f flag needs superuser (bug in umount)
			umount test_mnt &>/dev/null
			umount -f test_mnt &>/dev/null
		fi
		$ECHO "${OK}"
	fi
	kill $GSPID2
	rm -rf test_client
	rmdir test_mnt
	fi
fi

# Can not use nc here because nc does not terminate on EOF from stdin.
# Socat can be configured to terminate 1 second after EOF has been received.
# need sleep 3 on RPI (slow system)
STDOUT_SLEEP=3
[[ -f /proc/cpuinfo ]] && grep Raspberry /proc/cpuinfo &>/dev/null && STDOUT_SLEEP=3
export STDOUT_SLEEP

if [[ " ${tests[*]} " =~ ' 10.5 ' ]]; then
test_start -n "Running: gsocket nc #10.5 (stdin)........................."
GSPID1="$(sh -c '(cat test4k.dat; sleep $STDOUT_SLEEP) | GSOCKET_DEBUG=1 GSOCKET_ARGS="-Lserver_gs.log" gsocket -k id_sec.txt $NC $NC_EOF_ARG $NC_LISTEN_ARG 31337 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test1k.dat; sleep $STDOUT_SLEEP) | GSOCKET_DEBUG=1 GSOCKET_ARGS="-w -Lclient_gs.log" gsocket -k id_sec.txt $NC $NC_EOF_ARG -v gsocket 31337 2>client_err.txt >client_out.dat & echo ${!}')"
waitk $GSPID2
kill $GSPID1 &>/dev/null
md5fail 1 test1k.dat server_out.dat
md5fail 2 test4k.dat client_out.dat
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 10.5.1 ' ]]; then
test_start -n "Running: gsocket nc #10.5.1 (nc server)..................."
export PORTSEC="31337-$(cat id_sec.txt)"
GSPID1="$(sh -c '(cat test4k.dat; sleep $STDOUT_SLEEP) | GSOCKET_DEBUG=1 GSOCKET_ARGS="-Lserver_gs.log" gs-netcat -s $PORTSEC -l 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test1k.dat; sleep $STDOUT_SLEEP) | GSOCKET_DEBUG=1 GSOCKET_ARGS="-w -Lclient_gs.log" gsocket -k id_sec.txt $NC $NC_EOF_ARG -v gsocket 31337 2>client_err.txt >client_out.dat & echo ${!}')"
waitk $GSPID2
kill $GSPID1 &>/dev/null
md5fail 1 test1k.dat server_out.dat
md5fail 2 test4k.dat client_out.dat
$ECHO "${OK}"
fi

if [[ " ${tests[*]} " =~ ' 10.5.2 ' ]]; then
test_start -n "Running: gsocket nc #10.5.2 (nc client)..................."
export PORTSEC="31337-$(cat id_sec.txt)"
GSPID1="$(sh -c '(cat test4k.dat; sleep $STDOUT_SLEEP) | GSOCKET_DEBUG=1 GSOCKET_ARGS="-Lserver_gs.log" gsocket -k id_sec.txt $NC $NC_EOF_ARG $NC_LISTEN_ARG 31337 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test1k.dat; sleep $STDOUT_SLEEP) | GSOCKET_DEBUG=1 GSOCKET_ARGS="-w -Lclient_gs.log" gs-netcat -s $PORTSEC 2>client_err.txt >client_out.dat & echo ${!}')"
waitk $GSPID2
kill $GSPID1 &>/dev/null
md5fail 1 test1k.dat server_out.dat
md5fail 2 test4k.dat client_out.dat
$ECHO "${OK}"
fi


if [[ " ${tests[*]} " =~ ' 10.6 ' ]]; then
test_start -n "Running: gsocket socat #10.6 (stdin)......................"
if ! socat -h 2>/dev/null | grep socks4 &>/dev/null; then
	skip "(no socat)"
elif [[ "$OSTYPE" =~ solaris ]]; then
	# On Solaris the socat binary is 32 bit (but our gs_so lib is 64).
	# Loader wont work.
	skip "(32-bit)"
else
	# Can not use nc here because nc does not terminate on EOF from stdin.
	# Socat can be configured to terminate 1 second after EOF has been received.
	GSPID1="$(sh -c 'gsocket -k id_sec.txt socat -T1 -,ignoreeof TCP-LISTEN:31337 <test4k.dat 2>server_err.txt >server_out.dat & echo ${!}')"
	GSPID2="$(sh -c 'GSOCKET_ARGS=-w gsocket -k id_sec.txt socat -T1 -,ignoreeof TCP:gsocket:31337 <test1k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
	waitk $GSPID2
	kill $GSPID1 &>/dev/null
	md5fail 1 test1k.dat server_out.dat
	md5fail 2 test4k.dat client_out.dat
	$ECHO "${OK}"
fi
fi

if [[ " ${tests[*]} " =~ ' 10.7 ' ]]; then
test_start -n "Running: gsocket ssh #10.7 (stdin)........................"
if [[ "$OSTYPE" == *"solaris"* ]]; then
	# Solaris SSHD does not work unless it's run as root (some PAM shit)
	# Also needs -4 flag to run as IPv4 only (still, PAM shit afterwards)
	skip "(needs root)"
else
	[[ -f ssh_host_rsa_key ]] || ssh-keygen -q -N "" -t rsa -b 2048 -f ssh_host_rsa_key
	[[ -d ~/.ssh ]] || mkdir ~/.ssh
	[[ -f id_rsa ]] || ssh-keygen -q -N "" -t rsa -b 2048 -f id_rsa
	[[ -f ~/.ssh/authorized_keys ]] && cp -a ~/.ssh/authorized_keys ~/.ssh/authorized_keys-backup
	cat id_rsa.pub >>~/.ssh/authorized_keys
	SSHD_BIN=$(which sshd 2>/dev/null)
	[[ -z $SSHD_BIN ]] && SSHD_BIN="/usr/sbin/sshd"
	[[ -z $SSHD_BIN ]] && SSHD_BIN="/usr/lib/ssh/sshd"
	export SSHD_BIN
	[[ -f "$SSHD_BIN" ]] || { echo >&2 "sshd not found"; exit 255; }
	GSPID1="$(sh -c 'gsocket -k id_sec.txt $SSHD_BIN -f /dev/null -o HostKey=${PWD}/ssh_host_rsa_key -p 31338 -D 2>server_err.txt >server_out.dat & echo ${!}')"
	GSPID2="$(sh -c 'GSOCKET_ARGS=-w gsocket -k id_sec.txt ssh -i id_rsa -o StrictHostKeyChecking=no -p 31338 ${LOGNAME}@gsocket echo Hello World 2>client_err.txt >client_out.dat & echo ${!}')"
	waitk $GSPID2
	kill $GSPID1 &>/dev/null
	[[ -f ~/.ssh/authorized_keys-backup ]] && cp -a ~/.ssh/authorized_keys-backup ~/.ssh/authorized_keys
	# rm ~/.ssh/authorized_keys-backup
	if [ "${MDHELLOW}" != "$(MD5 client_out.dat)" ]; then fail 1; fi
	$ECHO "${OK}"
fi
fi

if [ x"$1" == x ]; then
	### Clean-up
	test_start ""
fi
exit 0

