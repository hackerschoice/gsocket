#! /bin/bash

#export GSOCKET_IP=127.0.0.1
#export GSOCKET_PORT=31337

# Sleep for connection time (CT). On localhost this can be 0.1
SLEEP_CT=0.5

if [ x"$GSOCKET_IP" == "x127.0.0.1" ]; then
	SLEEP_CT=0.1
fi

PATH=~/usr/bin:$PATH

SLEEP_WD=15	# Max timeout to wait for a process to finish receiving...
MD5="md5 -q"
OK="....[\033[1;32mOK\033[0m]"
FAIL="[\033[1;31mFAILED\033[0m]"
SKIP="[\033[1;33mskipping\033[0m]"
ECHO="echo -e"
tests="1.1 "
tests+="2.1 2.2 "
tests+="3.1 "
tests+="4.1 4.2 "
tests+="5.1 5.2 5.3 5.4 "
tests+="5.5 "		# cleartext
tests+="6.1 6.2 6.3 6.4 6.5 6.6 "
tests+="6.7 "		# cleartext
tests+="7.1 7.2 7.3 "
tests+="8.1 8.2 8.3 "
tests+="9.1 9.2 9.3 "

# tests="2.1 "
#tests="5.2"
# tests="6.1"
# tests="6.1 6.2 6.3 6.4 7.1 7.2"
# tests="8.1 8.2 8.3"
# tests="6.5 6.6"

if [ x"$1" != x ]; then
	tests="$@ "
fi

#OPTS="-k ./id_sec.txt"
#OPTS+=" -C"

# echo "Tests: ${tests}"
mk_dummy()
{
        [ -f "$1" ] || dd bs=1024 count=$2 if=/dev/urandom of="$1" 2>/dev/null
}
mk_dummy test1k.dat 1
mk_dummy test4k.dat 4
mk_dummy test50k.dat 50
mk_dummy test1M.dat 1024
mk_dummy test5M.dat 5120
mk_dummy test50M.dat 51200
echo "Fubar" >>test50M.dat	# Make it an odd length
MD50MB="`$MD5 test50M.dat`"
MD5MB="`$MD5 test5M.dat`"
MD1MB="`$MD5 test1M.dat`"

test_start()
{
	rm -f client_out.dat server_out.dat server_err.txt client_err.txt server[123]_out.dat client[12]_out.dat server[123]_err.txt client[12]_err.txt nc[123]_out.dat nc[123]_err.txt
	[[ x"$1" != x ]] && $ECHO $@
}

fail()
{
	$ECHO ${FAIL}-$@
	exit 255
}

skip()
{
	$ECHO ${SKIP} $@
}

# Wait until a process has termianted or kill it after SLEEP_WD seconds..
waitkp()
{
	x=0;
	rounds=`bc <<<"$SLEEP_WD / 0.1"`
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

# Wait for 2 files to become identical...
waitf()
{
	x=0;
	rounds=`bc <<<"$SLEEP_WD / 0.1"`
	while :; do
		if [ "`$MD5 $1`" == "`$MD5 $2`" ]; then
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
	x=0;
	rounds=`bc <<<"$SLEEP_WD / 0.1"`
	while :; do
		netstat -ant 2>/dev/null | grep LISTEN | grep "$1" &>/dev/null
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
	./gs-helloworld -g 2>/dev/null >id_sec.txt
}

# killall -9 gs-helloworld gs-pipe gs-full-pipe gs-netcat &>/dev/null
new_id

if [[ "$tests" =~ '1.1 ' ]]; then
### 1 - Hello World
test_start -n "Running: Hello world #1.1 ................................"
GSPID="$(sh -c './gs-helloworld -k id_sec.txt -l 2>server_err.txt >server_out.dat & echo ${!}')"
# sleep 0.5 required or otherwise kernel will send both strings in single
# tcp and that would result in a single read() call on other side.
sleep_ct && (echo "Hello World"; sleep 1; echo "That's the end") | ./gs-helloworld -k id_sec.txt 2>client_err.txt >client_out.dat
waitk $GSPID
if [ "`$MD5 client_out.dat`" != "628eca04c4cb6c8f539381be1c5cd325" ]; then fail 1; fi
if [ "`$MD5 server_out.dat`" != "333a867bef92d4712101e4a4b637740c" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '2.1 ' ]]; then
### 2 - Pipe
# Normal (server listening, client connecting)
test_start -n "Running: pipe #2.1 ......................................."
GSPID="$(sh -c './gs-pipe -k id_sec.txt -l 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct && ./gs-pipe -k id_sec.txt <test50k.dat 2>client_err.txt >client_out.dat
waitk $GSPID
if [ "`$MD5 test50k.dat`" != "`$MD5 server_out.dat`" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '2.2 ' ]]; then
### Waiting client test
test_start -n "Running: pipe #2.2 (waiting for server)..................."
GSPID="$(sh -c './gs-pipe -k id_sec.txt -w <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct && ./gs-pipe -k id_sec.txt -l 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "`$MD5 test50k.dat`" != "`$MD5 server_out.dat`" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '3.1 ' ]]; then
### Impersonate 'listen'
test_start -n "Running: pipe #3.1 (auth token)..........................."
GS1PID="$(sh -c './gs-pipe -k id_sec.txt -l -a player-alice 2>server1_err.txt >server1_out.dat & echo ${!}')"
GS2PID="$(sh -c './gs-pipe -k id_sec.txt -l -a player-alice 2>server2_err.txt >server2_out.dat & echo ${!}')"
# Next server should not be allowed to listen (wrong -a key)
sleep_ct
./gs-pipe -k id_sec.txt -l -a player-mallory 2>server3_err.txt >server3_out.dat
RET=$?
if [ $RET -ne 255 ]; then fail 1; fi
# Here: Two servers are still running...
./gs-pipe -k id_sec.txt <test50k.dat 2>client_err.txt >client_out.dat
./gs-pipe -k id_sec.txt <test50k.dat 2>client_err.txt >client_out.dat
waitk $GS1PID $GS2PID &>/dev/null
if [ "`$MD5 test50k.dat`" != "`$MD5 server1_out.dat`" ]; then fail 2; fi
if [ "`$MD5 test50k.dat`" != "`$MD5 server2_out.dat`" ]; then fail 3; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '4.1' ]]; then
### Client to become a server if no server is listening
test_start -n "Running: pipe #4.1 (become server if possible)............"
GSPID="$(sh -c './gs-pipe -k id_sec.txt -A 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct
./gs-pipe -k id_sec.txt -A <test50k.dat 2>client_err.txt >client_out.dat
waitk $GSPID
if [ "`$MD5 test50k.dat`" != "`$MD5 server_out.dat`" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '4.2' ]]; then
# Client already waiting. 2nd client to become server (if no server available)
test_start -n "Running: pipe #4.2 (..while client waiting)..............."
GSPID="$(sh -c './gs-pipe -k id_sec.txt -w <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
./gs-pipe -k id_sec.txt -A 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "`$MD5 test50k.dat`" != "`$MD5 server_out.dat`" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.1' ]]; then
test_start -n "Running: full-pipe #5.1..................................."
GSPID="$(sh -c './gs-full-pipe -k id_sec.txt -A <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
./gs-full-pipe -k id_sec.txt -A <test50k.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "`$MD5 test50k.dat`" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test50k.dat`" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.2' ]]; then
test_start -n "Running: full-pipe #5.2 (50MB)............................"
GSPID="$(sh -c './gs-full-pipe -k id_sec.txt -A <test50M.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
./gs-full-pipe -k id_sec.txt -A <test50M.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$MD50MB" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "$MD50MB" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.3' ]]; then
test_start -n "Running: full-pipe #5.3 (assym sizes, large server)......."
GSPID="$(sh -c './gs-full-pipe -k id_sec.txt -A <test1M.dat 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct
sleep 1
./gs-full-pipe -A -k id_sec.txt <test50k.dat 2>client_err.txt >client_out.dat
waitk $GSPID &>/dev/null
# if [ "$MD50MB" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test1M.dat`" != "`$MD5 client_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test50k.dat`" != "`$MD5 server_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.4' ]]; then
test_start -n "Running: full-pipe #5.4 (assym sizes, small server)......."
GSPID="$(sh -c './gs-full-pipe -k id_sec.txt -A <test50k.dat 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct
sleep 1
./gs-full-pipe -A -k id_sec.txt <test1M.dat 2>client_err.txt >client_out.dat
waitk $GSPID &>/dev/null
# if [ "$MD50MB" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test1M.dat`" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test50k.dat`" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.5' ]]; then
test_start -n "Running: full-pipe #5.5 (assymetric sizes, clear)........."
GSPID="$(sh -c './gs-full-pipe -k id_sec.txt -AC <test1M.dat 2>server_err.txt >server_out.dat & echo ${!}')"
sleep_ct
./gs-full-pipe -k id_sec.txt -AC <test50k.dat 2>client_err.txt >client_out.dat
waitk $GSPID
if [ "$MD1MB" != "`$MD5 client_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test50k.dat`" != "`$MD5 server_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '6.1' ]]; then
test_start -n "Running: netcat #6.1 (stdin, 1MB)........................."
GSPID="$(sh -c './gs-netcat -k id_sec.txt -w <test1M.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
./gs-netcat -k id_sec.txt -l <test1M.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$MD1MB" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "$MD1MB" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '6.2' ]]; then
test_start -n "Running: netcat #6.2 (stdin, assymetric sizes)............"
GSPID="$(sh -c './gs-netcat -k id_sec.txt -w <test1M.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
./gs-netcat -k id_sec.txt -l <test50k.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$MD1MB" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test50k.dat`" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '6.3' ]]; then
test_start -n "Running: netcat #6.3 (stdin, assym sizes, kill client)...."
GSPID1="$(sh -c '(cat test4k.dat; sleep 30) | ./gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test1k.dat; sleep 30) | ./gs-netcat -k id_sec.txt -l 2>server_err.txt >server_out.dat & echo ${!}')"
# sleep_ct
waitf test4k.dat server_out.dat
waitf test1k.dat client_out.dat
kill -9 $GSPID1 &>/dev/null
waitk $GSPID2
if [ "`$MD5 test4k.dat`" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test1k.dat`" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '6.4' ]]; then
test_start -n "Running: netcat #6.4 (stdin, assym sizes, kill server)...."
GSPID1="$(sh -c '(cat test4k.dat; sleep 30) | ./gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test1k.dat; sleep 30) | ./gs-netcat -k id_sec.txt -l 2>server_err.txt >server_out.dat & echo ${!}')"
waitf test4k.dat server_out.dat
waitf test1k.dat client_out.dat
kill -9 $GSPID2 &>/dev/null
waitk $GSPID1
if [ "`$MD5 test4k.dat`" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test1k.dat`" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '6.5' ]]; then
test_start -n "Running: netcat #6.5 (/dev/null C2S)......................"
GSPID="$(sh -c './gs-netcat -k id_sec.txt -w </dev/null 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
./gs-netcat -k id_sec.txt -l <test4k.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ -s server_out.dat ]; then fail 1; fi
if [ "`$MD5 test4k.dat`" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '6.6' ]]; then
test_start -n "Running: netcat #6.6 (/dev/null S2C)......................"
GSPID="$(sh -c './gs-netcat -k id_sec.txt -w <test4k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
./gs-netcat -k id_sec.txt -l </dev/null 2>server_err.txt >server_out.dat
waitk $GSPID
if [ -s client_out.dat ]; then fail 1; fi
if [ "`$MD5 test4k.dat`" != "`$MD5 server_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '6.7' ]]; then
test_start -n "Running: netcat #6.7 (stdin, assymetric sizes, clear)....."
GSPID="$(sh -c './gs-netcat -k id_sec.txt -wC <test1M.dat 2>client_err.txt >client_out.dat & echo ${!}')"
sleep_ct
./gs-netcat -k id_sec.txt -lC <test50k.dat 2>server_err.txt >server_out.dat
waitk $GSPID
if [ "$MD1MB" != "`$MD5 server_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test50k.dat`" != "`$MD5 client_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '7.1' ]]; then
test_start -n "Running: netcat #7.1 (cmd, multi connect)................."
GSPID1="$(sh -c './gs-netcat -k id_sec.txt -l -e "echo Hello World" 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c './gs-netcat -k id_sec.txt -w </dev/null 2>client2_err.txt >client2_out.dat & echo ${!}')"
GSPID3="$(sh -c './gs-netcat -k id_sec.txt -w </dev/null 2>client3_err.txt >client3_out.dat & echo ${!}')"
sleep 1 # Give the gs-netcat -l server time to establish a new TCP to GS-NEtwork...
./gs-netcat -k id_sec.txt -w </dev/null 2>client_err.txt >client_out.dat
waitk $GSPID2 $GSPID3
kill -9 $GSPID1	&>/dev/null # kill server last...
if [ "`echo 'Hello World' | $MD5`" != "`$MD5 client_out.dat`" ]; then fail 1; fi
if [ "`echo 'Hello World' | $MD5`" != "`$MD5 client2_out.dat`" ]; then fail 2; fi
if [ "`echo 'Hello World' | $MD5`" != "`$MD5 client3_out.dat`" ]; then fail 3; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '7.2' ]]; then
test_start -n "Running: netcat #7.2 (shell, exit)........................"
GSPID1="$(sh -c './gs-netcat -k id_sec.txt -l -e /bin/sh 2>server_err.txt >server_out.dat & echo ${!}')"
echo "echo; date; echo Hello World; exit" | ./gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat
sleep_ct
kill $GSPID1
if [ "`echo 'Hello World' | $MD5`" != "`tail -n1 client_out.dat | $MD5`" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '7.3' ]]; then
test_start -n "Running: netcat #7.3 (pty shell, exit)...................."
GSPID1="$(sh -c './gs-netcat -k id_sec.txt -l -i 2>server_err.txt >server_out.dat & echo ${!}')"
echo "echo; date; echo Hello World; exit" | ./gs-netcat -k id_sec.txt -w 2>client_err.txt >client_out.dat
sleep_ct
kill $GSPID1 
tail -n2 client_out.dat | grep 'Hello World' &>/dev/null
if [ $? -ne 0 ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.1' ]]; then
test_start -n "Running: netcat #8.1 (port forward server side)..........."
GSPID1="$(sh -c './gs-netcat -k id_sec.txt -l -d 127.0.0.1 -p 12345 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c '(sleep 10) | nc -nl 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
waittcp 12345
GSPID3="$(sh -c './gs-netcat -k id_sec.txt -w <test50k.dat 2>client_err.txt >client_out.dat & echo ${!}')"
waitf test50k.dat nc1_out.dat
kill -9 $GSPID1 $GSPID2 $GSPID3 &>/dev/null
if [ "`$MD5 test50k.dat`" != "`$MD5 nc1_out.dat`" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.2' ]]; then
# nc -> Port 12344 -> GS-NET -> Port 12345 -> nc -ln
test_start -n "Running: netcat #8.2 (port forward both sides)............"
GSPID1="$(sh -c './gs-netcat -k id_sec.txt -l -d 127.0.0.1 -p 12345 2>server_err.txt >server_out.dat & echo ${!}')"
GSPID2="$(sh -c '(sleep 10) | nc -nl 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
GSPID3="$(sh -c './gs-netcat -k id_sec.txt -w -p 12344 2>server_err.txt >server_out.dat & echo ${!}')"
waittcp 12344
waittcp 12345
GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | nc -vn 127.1 12344 >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
waitf test50k.dat nc1_out.dat
kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
if [ "`$MD5 test50k.dat`" != "`$MD5 nc1_out.dat`" ]; then fail 1; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.3' ]]; then
# nc -> Port 12344 -> GS-NET -> Port 12345 -> nc -ln
# Bi-Directional
test_start -n "Running: netcat #8.3 (port forward both sides, bi-dir)...."
GSPID1="$(sh -c './gs-netcat -k id_sec.txt -l -d 127.0.0.1 -p 12345 2>server1_err.txt >server1_out.dat & echo ${!}')"
GSPID2="$(sh -c '(cat test4k.dat; sleep 15) | nc -nl 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
GSPID3="$(sh -c './gs-netcat -k id_sec.txt -w -p 12344 2>client_err.txt >client_out.dat & echo ${!}')"
waittcp 12344
waittcp 12345
GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | nc -vn 127.1 12344 >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
waitf test50k.dat nc1_out.dat
waitf test4k.dat nc2_out.dat
kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
if [ "`$MD5 test50k.dat`" != "`$MD5 nc1_out.dat`" ]; then fail 1; fi
if [ "`$MD5 test4k.dat`" != "`$MD5 nc2_out.dat`" ]; then fail 2; fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '9.1' ]]; then
# SOCKS test socat -> port 1085 -> GS-NET -> Port 12345 -> nc -ln
test_start -n "Running: netcat #9.1 (socat/socks5)......................."
socat -h | grep socks5 >/dev/null
if [ $? -ne 0 ]; then
	skip "(no socat2)"
else
	GSPID1="$(sh -c './gs-netcat -k id_sec.txt -lS 2>server1_err.txt >server1_out.dat & echo ${!}')"
	GSPID2="$(sh -c '(cat test4k.dat; sleep 15) | nc -nl 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
	GSPID3="$(sh -c './gs-netcat -k id_sec.txt -p 1085 2>client_err.txt >client_out.dat & echo ${!}')"
	waittcp 1085
	waittcp 12345
	GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | socat -  "SOCKS5:localhost:12345 | TCP:127.1:1085" >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
	waitf test50k.dat nc1_out.dat
	waitf test4k.dat nc2_out.dat
	kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
	if [ "`$MD5 test50k.dat`" != "`$MD5 nc1_out.dat`" ]; then fail 1; fi
	if [ "`$MD5 test4k.dat`" != "`$MD5 nc2_out.dat`" ]; then fail 2; fi
	$ECHO "${OK}"
	fi
fi

if [[ "$tests" =~ '9.2' ]]; then
# SOCKS test socat -> port 1085 -> GS-NET -> Port 12345 -> nc -ln
test_start -n "Running: netcat #9.2 (socat/socks4)......................."
socat -h | grep socks4 >/dev/null
if [ $? -ne 0 ]; then
	skip "(no socat)"
else
	GSPID1="$(sh -c './gs-netcat -k id_sec.txt -lS 2>server1_err.txt >server1_out.dat & echo ${!}')"
	GSPID2="$(sh -c '(cat test4k.dat; sleep 15) | nc -nl 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
	GSPID3="$(sh -c './gs-netcat -k id_sec.txt -p 1085 2>client_err.txt >client_out.dat & echo ${!}')"
	waittcp 1085
	waittcp 12345
	GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | socat -  "SOCKS4:127.1:127.1:12345,socksport=1085" >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
	waitf test50k.dat nc1_out.dat
	waitf test4k.dat nc2_out.dat
	kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
	if [ "`$MD5 test50k.dat`" != "`$MD5 nc1_out.dat`" ]; then fail 1; fi
	if [ "`$MD5 test4k.dat`" != "`$MD5 nc2_out.dat`" ]; then fail 2; fi
	$ECHO "${OK}"
	fi
fi

if [[ "$tests" =~ '9.3' ]]; then
# SOCKS test socat -> port 1085 -> GS-NET -> Port 12345 -> nc -ln
test_start -n "Running: netcat #9.3 (socat/socks4a)......................"
socat -h | grep socks4 >/dev/null
if [ $? -ne 0 ]; then
	skip "(no socat)"
else
	GSPID1="$(sh -c './gs-netcat -k id_sec.txt -lS 2>server1_err.txt >server1_out.dat & echo ${!}')"
	GSPID2="$(sh -c '(cat test4k.dat; sleep 15) | nc -nl 12345 >nc1_out.dat 2>nc1_err.txt & echo ${!}')"
	GSPID3="$(sh -c './gs-netcat -k id_sec.txt -p 1085 2>client_err.txt >client_out.dat & echo ${!}')"
	waittcp 1085
	waittcp 12345
	GSPID4="$(sh -c '(cat test50k.dat; sleep 15) | socat -  "SOCKS4a:127.1:localhost:12345,socksport=1085" >nc2_out.dat 2>nc2_err.txt & echo ${!}')"
	waitf test50k.dat nc1_out.dat
	waitf test4k.dat nc2_out.dat
	kill -9 $GSPID1 $GSPID2 $GSPID3 $GSPID4 &>/dev/null 
	if [ "`$MD5 test50k.dat`" != "`$MD5 nc1_out.dat`" ]; then fail 1; fi
	if [ "`$MD5 test4k.dat`" != "`$MD5 nc2_out.dat`" ]; then fail 2; fi
	$ECHO "${OK}"
	fi
fi

if [ x"$1" == x ]; then
	### Clean-up
	test_start ""
fi
exit 0

