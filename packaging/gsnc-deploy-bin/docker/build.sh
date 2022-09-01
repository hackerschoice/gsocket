#! /bin/sh
#  ^^^^^^^Mutli OS must use /bin/sh (alpine uses ash, debian uses dash)

# This script is executed inside a docker container.
# It is used to build gs-netcat as staticly linked binary for various OSes.

test -d /gsocket-src || { echo >&2 "/gsocket-src does not exists."; exit 255; }
test -d /gsocket-build || { echo >&2 "/gsocket-build does not exists."; exit 255; }

cd /gsocket-src && \
./configure --prefix=/root/usr --enable-stealth --enable-static $(cat /gsocket-src/configure-parameters.txt) && \
make clean all && \
strip tools/gs-netcat && \
{ command -v upx >/dev/null && upx tools/gs-netcat; true; } && \
# Test execute the binary (unless cross compiler)
{ grep host /gsocket-src/configure-parameters.txt >/dev/null || tools/gs-netcat -g || { rm -f tools/gs-netcat; exit 255; }; } && exit

exit 255
