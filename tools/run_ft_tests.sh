#! /bin/bash

command -v md5 >/dev/null 2>&1 		&& MD5(){ md5 -q "${1}";}
command -v md5sum >/dev/null 2>&1 	&& MD5() { md5sum "${1}" | cut -f1 -d' ';}

IODIR=ft_test_io
OK="....[\033[1;32mOK\033[0m]"
FAIL="[\033[1;31mFAILED\033[0m]"
ECHO="echo -e"

mk_dummy()
{
        [ -f "$1" ] || dd bs=1024 count=$2 if=/dev/urandom of="$1" 2>/dev/null
}

mk_dummy test1k.dat 1
mk_dummy test4k.dat 4
mk_dummy test8k.dat 8

test_start()
{
	mkdir -p "${IODIR}" &>/dev/null
	rm -rf "${IODIR}/"*.dat &>/dev/null
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

run_put()
{
	socat SYSTEM:"./filetransfer-test c $* 2>client.log" SYSTEM:"(cd ${IODIR}; ../filetransfer-test s 2>../server.log)"
}


# tests="1.0 "
# tests+="1.1 "
# tests+="1.2 "
tests+="1.3 "
# tests+="2.1 2.2 "
# tests+="2.3 "
# tests+="3.1 3.2 3.3 "
# tests+="4.1 "
# tests+="4.2 "
# tests+="4.3 "

if [[ "$tests" =~ '1.0 ' ]]; then
test_start -n "Running #1.0 (put 1 file).................................."
run_put test1k.dat
md5fail 1 test1k.dat "${IODIR}/test1k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '1.1 ' ]]; then
test_start -n "Running #1.1 (put 2 files)................................."
run_put test4k.dat test8k.dat
md5fail 1 test4k.dat "${IODIR}/test4k.dat"
md5fail 2 test8k.dat "${IODIR}/test8k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '1.2 ' ]]; then
test_start -n "Running #1.2 (non-exist)..................................."
run_put not-exists.dat
[[ -f "${IODIR}/not-exists.dat" ]] && fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '1.3 ' ]]; then
test_start -n "Running #1.3 (absolute file)..............................."
# run_put /etc/hosts
cp test1k.dat ./foo/bar/test1k.dat
run_put ./foo/bar/test1k.dat
# run_put /./etc/hosts ../tools/test1k.dat
ls -al "${IODIR}/foo/bar"
exit
[[ -f "${IODIR}/etc/hosts" ]] && fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '2.1 ' ]]; then
test_start -n "Running #2.1 (src is larger, restart)......................"
dd bs=1k count=5 if=test8k.dat of="${IODIR}/test8k.dat" &>/dev/null
run_put test4k.dat test8k.dat
md5fail 1 test8k.dat "${IODIR}/test8k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '2.2 ' ]]; then
test_start -n "Running #2.2 (dst is larger, overwrite)...................."
cp test8k.dat "${IODIR}/test4k.dat"
run_put test4k.dat
md5fail 1 test4k.dat "${IODIR}/test4k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '2.3 ' ]]; then
test_start -n "Running #2.3 (zero src size)..............................."
touch zero.dat
run_put zero.dat
md5fail 1 zero.dat "${IODIR}/zero.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '3.1 ' ]]; then
test_start -n "Running #3.2 (write-error 0-sized dst)....................."
touch "${IODIR}/test4k.dat"
chmod 400 "${IODIR}/test4k.dat"
run_put test4k.dat
[[ x`stat -f%z "${IODIR}/test4k.dat"` = x0 ]] || fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '3.2 ' ]]; then
test_start -n "Running #3.2 (write-error partial)........................."
cp test4k.dat "${IODIR}/test8k.dat"
chmod 400 "${IODIR}/test8k.dat"
run_put test8k.dat
md5fail 1 test4k.dat "${IODIR}/test8k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '3.3 ' ]]; then
test_start -n "Running #3.3 (dir not writeable)..........................."
chmod a-w "${IODIR}"
run_put test4k.dat
chmod u+w "${IODIR}"
[[ -f "${IODIR}/test4k.dat" ]] && fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '4.1 ' ]]; then
test_start -n "Running #4.1 (permission).................................."
chmod 462 test4k.dat
# chmod u+s test4k.dat # On MacOS our own app can not set +s...
run_put test4k.dat
[[ x`stat -f%A "test4k.dat"` = x`stat -f%A "${IODIR}/test4k.dat"` ]] || fail 1
chmod 644 "${IODIR}/test4k.dat"
$ECHO "${OK}"
fi

if [[ "$tests" =~ '4.2 ' ]]; then
test_start -n "Running #4.2 (mtime)......................................."
touch -r /etc/hosts test4k.dat
run_put test4k.dat
[[ x`stat -f%a "test4k.dat"` = x`stat -f%a "${IODIR}/test4k.dat"` ]] || fail 1
$ECHO "${OK}"
fi

if [[ "$tests" =~ '4.3 ' ]]; then
test_start -n "Running #4.2 (zero-size, mtime)............................"
touch -r /etc/hosts zero.dat
run_put zero.dat
[[ x`stat -f%a "zero.dat"` = x`stat -f%a "${IODIR}/zero.dat"` ]] || fail 1
$ECHO "${OK}"
fi

