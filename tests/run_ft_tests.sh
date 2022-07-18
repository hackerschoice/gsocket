#! /bin/bash

command -v md5 >/dev/null 2>&1 		&& MD5(){ md5 -q "${1}";}
command -v md5sum >/dev/null 2>&1 	&& MD5(){ md5sum "${1}" | cut -f1 -d' ';}

if [[ $(uname) =~ Darwin ]]; then
	FSIZE(){ stat -f%z "$1";}
	FACCESS(){ stat -f%A "$1";}
	FMTIME(){ stat -f%m "$1";}
	FSTAT(){ stat -f%A-%m-%z "$1";}
	DSTAT(){ stat -L -f%A-%m "$1";}
elif [[ $(uname) =~ FreeBSD ]]; then
	FSIZE(){ stat -f%z "$1";}
	FACCESS(){ stat -f%p "$1";}
	FMTIME(){ stat -f%m "$1";}
	FSTAT(){ stat -f%p-%m-%z "$1";}
	DSTAT(){ stat -L -f%p-%m "$1";}
elif [[ -f /bin/busybox ]]; then
	FSIZE(){ stat -c%s "$1";}
	FACCESS(){ stat -c%a "$1";}
	FMTIME(){ stat -c%Y "$1";}
	FSTAT(){ stat -c%a-%Y-%s "$1";}
	DSTAT(){ stat -L -c%a-%Y "$1";}
else
	FSIZE(){ stat --format=%s "$1";}
	FACCESS(){ stat --format=%a "$1";}
	FMTIME(){ stat --format=%Y "$1";}
	FSTAT(){ stat --format=%a-%Y-%s "$1";}
	DSTAT(){ stat -L --format=%a-%Y "$1";}
fi

IODIR="${PWD}/ft_test_dst"
IODIRSRC="ft_test_src"
LOGDIR="${PWD}"
OK="....[\033[1;32mOK\033[0m]"
FAIL="[\033[1;31mFAILED\033[0m]"
SKIP="[\033[1;33mskipping\033[0m]"
BINDIR="${PWD}/../tools"
ECHO="echo -e"
BIN="${BINDIR}/filetransfer-test"

[[ -f "${BIN}" ]] || { echo "${BIN} not found. Try ./configure --enable-tests"; exit 255; }

if [[ $(uname) =~ Darwin ]]; then
	export PATH=$HOME/usr/bin:$PATH
fi
command -v socat >/dev/null 2>&1 || { $ECHO >&2 "socat not installed. ${SKIP}"; exit 0; }


mk_dummy()
{
        [ -f "$1" ] || dd bs=1024 count=$2 if=/dev/urandom of="$1" 2>/dev/null
}

mk_dummy test1k.dat 1
mk_dummy test4k.dat 4
mk_dummy test8k.dat 8

rm -rf "${IODIRSRC}/foo"
mkdir -p "${IODIRSRC}/foo/bar"
mkdir -p "${IODIRSRC}/foo/dir_empty"
cp test1k.dat "${IODIRSRC}/"
cp test1k.dat "${IODIRSRC}/foo/bar/"
cp test1k.dat "${IODIRSRC}/foo/.rcfile1"
cp test4k.dat "${IODIRSRC}/foo/"
cp test4k.dat "${IODIRSRC}/foo/bar/.rcfile2"
cp test8k.dat "${IODIRSRC}/"
touch "${IODIRSRC}/zero.dat"

test_start()
{
	rm -rf "${IODIR}/" &>/dev/null
	mkdir -p "${IODIR}" &>/dev/null
	[[ x"$1" != x ]] && $ECHO $*
}

fail()
{
	$ECHO "${FAIL}"-$*
	exit 255
}

# code file1 file2
md5fail()
{
	[[ "$(MD5 ${2})" != "$(MD5 ${3})" ]] && fail $1;
}

fail_file_count()
{
	# Do not quote so that globbing takes effect.
	nf_src=$(find $2 -xdev -type f -o -type d | wc -l)
	nf_dst=$(find $3 -xdev -type f -o -type d | wc -l)
	[[ $nf_src -eq $nf_dst ]] || fail $1
}

fail_file_bypipe()
{
	while read f; do
		if [ $(FSTAT "${2}/${f}") != $(FSTAT "${3}/${f}") ]; then
			echo "${f} not equal";
			fail $1
		fi
	done
}

fail_dir_bypipe()
{
	while read f; do
		if [ $(DSTAT "${2}/${f}") != $(DSTAT "${3}/${f}") ]; then
			echo "${f} not equal";
			fail $1
		fi
	done
}

# Recursively compare st_mode and mtime and fail if different
fail_dir_compare()
{
	(cd "$2"; find "$4" -xdev -type d) | fail_dir_bypipe "$1" "$2" "$3"
	(cd "$2"; find "$4" -xdev -type f) | fail_file_bypipe "$1" "$2" "$3"
}


run_put()
{
	# set -f disabled globbing
	# socat SYSTEM:"./filetransfer-test c $* 2>client.log" SYSTEM:"(cd ${IODIR}; ../filetransfer-test s 2>../server.log)"
	# socat SYSTEM:"set -f && ./filetransfer-test c $* 2>client.log" SYSTEM:"(cd ${IODIR}; ../filetransfer-test s 2>../server.log)"
	socat SYSTEM:"set -f && ${BIN} c $* 2>${LOGDIR}/client.log" SYSTEM:"(cd ${IODIR}; ${BIN} s 2>${LOGDIR}/server.log)"
}

# put with command 
run_putc()
{
	socat SYSTEM:"set -f && ${BIN} c \'$*\' 2>${LOGDIR}/client.log" SYSTEM:"(cd ${IODIR}; ${BIN} s 2>${LOGDIR}/server.log)"
}

run_get()
{
	# set -f disabled globbing
	socat SYSTEM:"(cd ${IODIR}; set -f && ${BIN} C $* 2>${LOGDIR}/client.log)" SYSTEM:"(cd ${IODIRSRC}; ${BIN} s 2>${LOGDIR}/server.log)"
}

run_get2()
{
	# set -f disabled globbing
	socat SYSTEM:"(cd ${IODIR}; set -f && ${BIN} C $* 2>${LOGDIR}/client.log)" SYSTEM:"(cd ${IODIRSRC}/foo; ${BIN} s 2>${LOGDIR}/server.log)"
}

# Server is a bad actor and send ../../../shit.dat as reply for any request
run_get_dst()
{
	# set -f disabled globbing
	socat SYSTEM:"(cd ${IODIR}/foo; set -f && ${BIN} C test4k.dat 2>${LOGDIR}/client.log)" SYSTEM:"(cd ${IODIRSRC}/foo; ${BIN} s $* 2>${LOGDIR}/server.log)"
}

run_getc()
{
	socat SYSTEM:"(cd ${IODIR}; set -f && ${BIN} C \'$*\' 2>${LOGDIR}/client.log)" SYSTEM:"(cd ${IODIRSRC}; ${BIN} s 2>${LOGDIR}/server.log)"
}

tests="1.0 "
tests+="1.1 "
tests+="1.2 "
tests+="1.3 "
tests+="2.1 2.2 "
tests+="2.3 "
tests+="3.1 3.2 "
tests+="3.3 "
tests+="3.4 "
tests+="4.1 "
tests+="4.2 "
tests+="4.3 "
tests+="4.4 "
tests+="5.1 "
tests+="5.2 "
tests+="5.3 "
tests+="5.4 "
tests+="5.5 "
tests+="5.6 "
tests+="5.7 "
tests+="5.8 "

tests+="8.1 "
tests+="8.2 "
tests+="8.3 "
tests+="8.4 "
tests+="8.5 "
tests+="8.6 "
tests+="8.7 "
tests+="8.8 "
tests+="8.9 "

tests+="9.1 "
tests+="9.2 "

if [ x"$1" != x ]; then
	tests="$@ "
fi

if [[ "$tests" =~ '1.0 ' ]]; then
test_start -n "Running #1.0 (put 1 file)................................."
run_put test1k.dat
md5fail 1 test1k.dat "${IODIR}/test1k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '1.1 ' ]]; then
test_start -n "Running #1.1 (put 2 files)................................"
run_put test4k.dat test8k.dat
md5fail 1 test4k.dat "${IODIR}/test4k.dat"
md5fail 2 test8k.dat "${IODIR}/test8k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '1.2 ' ]]; then
test_start -n "Running #1.2 (non-exist).................................."
run_put not-exists.dat
[[ -f "${IODIR}/not-exists.dat" ]] && fail 1
$ECHO "${OK}"
fi

run_put_fail()
{
	rm -rf "${IODIR}/" &>/dev/null
	mkdir -p "${IODIR}" &>/dev/null
	run_put "$2"
	[[ -f "$3" ]] || fail "$1"
	rm -f "$3"
}

if [[ "$tests" =~ '1.3 ' ]]; then
test_start -n "Running #1.3 (absolute file).............................."
run_put_fail 1 "${IODIRSRC}/foo/bar/test1k.dat" "${IODIR}/test1k.dat"
run_put_fail 2 "${IODIRSRC}/foo/bar/./test1k.dat" "${IODIR}/test1k.dat"
run_put_fail 3 "./${IODIRSRC}/foo/bar/test1k.dat" "${IODIR}/test1k.dat"
run_put_fail 4 "${IODIRSRC}/foo/./bar/test1k.dat" "${IODIR}/bar/test1k.dat"
run_put_fail 5 "././${IODIRSRC}/foo/bar/test1k.dat" "${IODIR}/${IODIRSRC}/foo/bar/test1k.dat"
run_put_fail 6 "${IODIRSRC}/foo/../foo/bar/test1k.dat" "${IODIR}/test1k.dat"
run_put_fail 7 "${IODIRSRC}/foo/../foo/./bar/test1k.dat" "${IODIR}/bar/test1k.dat"
run_put_fail 8 "${PWD}/${IODIRSRC}/foo/bar/test1k.dat" "${IODIR}/test1k.dat"
### run_put foo/./../foo/../foo/bar/test1k.dat # escape. wanted behavior (?).
$ECHO "${OK}"
fi

if [[ "$tests" =~ '2.1 ' ]]; then
test_start -n "Running #2.1 (src is larger, restart)....................."
dd bs=1k count=5 if=test8k.dat of="${IODIR}/test8k.dat" &>/dev/null
run_put test4k.dat test8k.dat
md5fail 1 test8k.dat "${IODIR}/test8k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '2.2 ' ]]; then
test_start -n "Running #2.2 (dst is larger, overwrite)..................."
cp test8k.dat "${IODIR}/test4k.dat"
run_put test4k.dat
md5fail 1 test4k.dat "${IODIR}/test4k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '2.3 ' ]]; then
test_start -n "Running #2.3 (zero src size).............................."
touch zero.dat
run_put zero.dat
md5fail 1 zero.dat "${IODIR}/zero.dat"
$ECHO "${OK}"
fi


if [[ "$tests" =~ '3.1 ' ]]; then
test_start -n "Running #3.1 (write-error 0-sized dst)...................."
touch "${IODIR}/test4k.dat"
if [[ $(uname) =~ CYGWIN ]]; then
	chattr +r "${IODIR}/test4k.dat"
else
	chmod 400 "${IODIR}/test4k.dat"
fi
run_put test4k.dat
[[ x`FSIZE "${IODIR}/test4k.dat"` = x0 ]] || fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '3.2 ' ]]; then
test_start -n "Running #3.2 (write-error partial)........................"
cp test4k.dat "${IODIR}/test8k.dat"
if [[ $(uname) =~ CYGWIN ]]; then
	chattr +r "${IODIR}/test8k.dat"
else
	chmod 400 "${IODIR}/test8k.dat"
fi
run_put test8k.dat
md5fail 1 test4k.dat "${IODIR}/test8k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '3.3 ' ]]; then
test_start -n "Running #3.3 (dir not writeable).........................."
if [[ $(uname) =~ CYGWIN ]]; then
	$ECHO "${SKIP}"
else
chmod a-w "${IODIR}"
run_put test4k.dat
[[ -f "${IODIR}/test4k.dat" ]] && fail 1
$ECHO "${OK}"
fi
fi

if [[ "$tests" =~ '3.4 ' ]]; then
test_start -n "Running #3.4 (src not readable)..........................."
if [[ $(uname) =~ CYGWIN ]]; then
	$ECHO "${SKIP}"
else
chmod a-r "${IODIRSRC}/test1k.dat"
run_put "${IODIRSRC}/test1k.dat"
[[ -f "${IODIR}/test1k.dat" ]] && fail 1
chmod a+r "${IODIRSRC}/test1k.dat"
$ECHO "${OK}"
fi
fi

if [[ "$tests" =~ '4.1 ' ]]; then
test_start -n "Running #4.1 (permission)................................."
chmod 462 test4k.dat
# chmod u+s test4k.dat # On MacOS our own app can not set +s...
run_put test4k.dat
[[ x`FACCESS "test4k.dat"` = x`FACCESS "${IODIR}/test4k.dat"` ]] || fail 1
chmod 644 test4k.dat
$ECHO "${OK}"
fi

if [[ "$tests" =~ '4.2 ' ]]; then
test_start -n "Running #4.2 (mtime)......................................"
touch -r /etc/hosts test4k.dat
run_put test4k.dat
[[ x`FMTIME "test4k.dat"` = x`FMTIME "${IODIR}/test4k.dat"` ]] || fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '4.3 ' ]]; then
test_start -n "Running #4.3 (zero-size, mtime)..........................."
touch -r /etc/hosts zero.dat
run_put zero.dat
[[ x`FMTIME "zero.dat"` = x`FMTIME "${IODIR}/zero.dat"` ]] || fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '4.4 ' ]]; then
test_start -n "Running #4.4 (put, empty directory)......................."
touch "${IODIR}/foo" # Place a file in its way (should be overwritten)
run_put "${IODIRSRC}/./foo/dir_empty"
[[ -d "${IODIR}/foo/dir_empty" ]] || fail 1
touch "${IODIR}/dir_empty" # Place a file in its way (should be overwritten)
run_put "${IODIRSRC}/foo/dir_empty"
[[ -d "${IODIR}/dir_empty" ]] || fail 2
rmdir "${IODIR}/dir_empty"
run_put "${IODIRSRC}/foo/dir_empty"
[[ -d "${IODIR}/dir_empty" ]] || fail 3
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.1 ' ]]; then
test_start -n "Running #5.1 (Globbing ./*)..............................."
run_put "${IODIRSRC}/*"
fail_file_count 1 "${IODIRSRC}/*" "${IODIR}/*" 
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.2 ' ]]; then
test_start -n "Running #5.2 (Globbing ./foo/.*).........................."
run_put "${IODIRSRC}/./foo/.*"
[[ $(find ${IODIR}/ -type f -o -type d | wc -l) -eq 3 ]] || fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.3 ' ]]; then
test_start -n "Running #5.3 (Globbing .*)................................"
(cd "${IODIRSRC}/foo" && run_put ".*")
[[ $(find ${IODIR}/ -type f -o -type d | wc -l) -eq 2 ]] || fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.4 ' ]]; then
test_start -n "Running #5.4 (Globbing foo)..............................."
(cd "${IODIRSRC}" && run_put "foo")
fail_file_count 1 "${IODIRSRC}/foo" "${IODIR}/foo" 
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.5 ' ]]; then
test_start -n "Running #5.5 (Globbing .)................................."
(cd "${IODIRSRC}" && run_put ".")
fail_file_count 1 "${IODIRSRC}/" "${IODIR}/" 
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.6 ' ]]; then
test_start -n "Running #5.6 (Globbing foo/).............................."
(cd "${IODIRSRC}" && run_put "foo/")
fail_file_count 1 "${IODIRSRC}/foo/" "${IODIR}/" 
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.7 ' ]]; then
test_start -n "Running #5.7 (put, globbing \$(find...*.dat)..............."
# (cd "${IODIRSRC}" && run_putc '\$(echo *.dat)')
(cd "${IODIRSRC}" && run_putc '\$(find . -type f -name \\*.dat)')
(cd "${IODIRSRC}" && find . -type f -name '*.dat') | fail_file_bypipe 1 "${IODIRSRC}" "${IODIR}"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '5.8 ' ]]; then
test_start -n "Running #5.8 (get, globbing \$(find...*.dat)..............."
run_getc '\$(find . -type f -name \\*.dat)'
(cd "${IODIRSRC}" && find . -type f -name '*.dat') | fail_file_bypipe 1 "${IODIRSRC}" "${IODIR}"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.1 ' ]]; then
test_start -n "Running #8.1 (get, 2 files)..............................."
run_get test8k.dat foo/bar/.rcfile2
md5fail 1 test8k.dat "${IODIR}/test8k.dat"
md5fail 2 test4k.dat "${IODIR}/.rcfile2"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.2 ' ]]; then
test_start -n "Running #8.2 (get, 2 files /./ test)......................"
run_get ./foo/bar/test1k.dat ./foo/./bar/test1k.dat
md5fail 1 test1k.dat "${IODIR}/test1k.dat"
md5fail 2 test1k.dat "${IODIR}/bar/test1k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.3 ' ]]; then
test_start -n "Running #8.3 (directory test)............................."
run_get foo/bar
md5fail 1 "${IODIRSRC}/foo/bar/test1k.dat" "${IODIR}/bar/test1k.dat"
md5fail 2 "${IODIRSRC}/foo/bar/.rcfile2" "${IODIR}/bar/.rcfile2"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.4 ' ]]; then
test_start -n "Running #8.4 (get, non-exist)............................."
run_get not-exists.dat foobar*noexist[1234].d[ab]t
[[ -f "${IODIR}/not-exists.dat" ]] && fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.5 ' ]]; then
test_start -n "Running #8.5 (get, ../test8k.dat)........................."
run_get2 ../test8k.dat ../foo ../foo/./bar
md5fail 1 "${IODIRSRC}/test8k.dat" "${IODIR}/test8k.dat"
fail_file_count 2 "${IODIRSRC}/foo" "${IODIR}/foo"
fail_file_count 3 "${IODIRSRC}/foo/bar" "${IODIR}/bar"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.6 ' ]]; then
test_start -n "Running #8.6 (get, /etc/hosts)............................"
if [[ $(uname) =~ CYGWIN ]]; then
run_get /etc/hosts /etc/./pki/tls/cert.pem /./etc/pki/tls/cert.pem
md5fail 1 "/etc/hosts" "${IODIR}/hosts"
md5fail 2 "/etc/pki/tls/cert.pem" "${IODIR}/pki/tls/cert.pem"
md5fail 3 "/etc/pki/tls/cert.pem" "${IODIR}/etc/pki/tls/cert.pem"
else
run_get /etc/hosts /etc/./ssh/ssh_config /./etc/ssh/ssh_config
md5fail 1 "/etc/hosts" "${IODIR}/hosts"
md5fail 2 "/etc/ssh/ssh_config" "${IODIR}/ssh/ssh_config"
md5fail 3 "/etc/ssh/ssh_config" "${IODIR}/etc/ssh/ssh_config"
fi
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.7 ' ]]; then
test_start -n "Running #8.7 (get, permission, mtime, zero)..............."
chmod 462 "${IODIRSRC}/test1k.dat"
chmod 624 "${IODIRSRC}/zero.dat"
chmod 3751 "${IODIRSRC}/foo/dir_empty"
touch -r /etc/hosts "${IODIRSRC}/test1k.dat" "${IODIRSRC}/zero.dat" "${IODIRSRC}/foo/dir_empty"
touch -r /etc "${IODIRSRC}/foo"
touch -r /etc "${IODIR}" "${IODIRSRC}"
run_get test1k.dat zero.dat ././foo/dir_empty
[[ $(FSTAT "${IODIRSRC}/test1k.dat") = $(FSTAT "${IODIR}/test1k.dat") ]] || fail 1
[[ $(FSTAT "${IODIRSRC}/zero.dat") = $(FSTAT "${IODIR}/zero.dat") ]] || fail 2
[[ $(DSTAT "${IODIRSRC}/foo/dir_empty") = $(DSTAT "${IODIR}/foo/dir_empty") ]] || fail 3
[[ $(DSTAT "${IODIRSRC}/foo") = $(DSTAT "${IODIRSRC}/foo") ]] || fail 4
[[ $(DSTAT "${IODIRSRC}") = $(DSTAT "${IODIR}") ]] || fail 5
chmod 644 "${IODIRSRC}/test1k.dat" "${IODIRSRC}/zero.dat"
chmod 755 "${IODIRSRC}/foo/dir_empty"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.8 ' ]]; then
test_start -n "Running #8.8 (get restart: dst is larger, smaller & zero)."
dd bs=1k count=5 if="${IODIRSRC}/test8k.dat" of="${IODIR}/test8k.dat" &>/dev/null
cp "${IODIRSRC}/test8k.dat" "${IODIR}/test1k.dat"
touch "${IODIR}/test4k.dat"
run_get test1k.dat test8k.dat foo/test4k.dat
md5fail 1 "${IODIRSRC}/test8k.dat" "${IODIR}/test8k.dat"
md5fail 2 "${IODIRSRC}/test1k.dat" "${IODIR}/test1k.dat"
md5fail 2 "${IODIRSRC}/foo/test4k.dat" "${IODIR}/test4k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '8.9 ' ]]; then
test_start -n "Running #8.9 (get, Server sending ../../../shit..........."
mkdir ${IODIR}/foo 
run_get_dst /tmp/0wned.dat
run_get_dst ./../../../../../../../../../../../../../tmp/0wned.dat
run_get_dst ../0wned.dat
[[ -e /tmp/0wned.dat ]] && fail 1
[[ -e "${IODIR}/0wned.dat" ]] && fail 2 
$ECHO "${OK}"
fi

# Find a local directory that contains some huge amount of files
try_find_bigdir()
{
	local dir

	[[ -n $bigdir ]] && return

	dir=$1
	[[ -n $QUICK ]] && dir=$2

	[[ ! -d "/usr/${dir}" ]] && return

	# return if it is to small
	[[ $(du -sk "/usr/${dir}"  | cut -f1) -lt 64 ]] && return

	bigdir="$dir"
}

unset bigdir
quick_dir="share/man/man4"
[[ $(uname) =~ CYGWIN ]] && quick_dir="share/man/man8" # Less huge
[[ $(uname) =~ FreeBSD ]] && quick_dir="share/man/man6" # Less huge
[[ $(uname) =~ SunOS ]] && quick_dir="share/man/man9p" # Less huge

try_find_bigdir share/man "${quick_dir}"
try_find_bigdir include include/bits

if [[ "$tests" =~ '9.1 ' ]]; then
test_start -n "Running #9.1 (HUGE put).........................."
if [[ -z $bigdir ]]; then
	$ECHO "${SKIP} (no files)"
else
run_put "/usr/./${bigdir}"
$ECHO -n "verify..."
fail_dir_compare 1 "/usr/${bigdir}" "${IODIR}/${bigdir}" .
$ECHO "${OK}"
fi
fi

if [[ "$tests" =~ '9.2 ' ]]; then
test_start -n "Running #9.2 (HUGE get).........................."
if [[ -z $bigdir ]]; then
	$ECHO "${SKIP} (no files)"
else
run_get "/usr/./${bigdir}"
$ECHO -n "verify..."
fail_dir_compare 1 "/usr/${bigdir}" "${IODIR}/${bigdir}" .
$ECHO "${OK}"
fi
fi


if [ x"$1" == x ]; then
	rm -rf "${IODIRSRC}" "${IODIR}"
fi


