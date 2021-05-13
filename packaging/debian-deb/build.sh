#! /bin/bash

test -d /gsocket-src || { echo >&2 "/gsocket-src does not exists."; exit 255; }
test -d /gsocket-deb || { echo >&2 "/gsocket-deb does not exists."; exit 255; }

[[ -z "$VER" ]] && { echo >&2 "VER not set"; exit 255; }

PREFIX="/gsocket-deb/build/gsocket_${VER}_all"
mkdir -p "${PREFIX}/DEBIAN" && \
sed "s/@@VER@@/$VER/" < /gsocket-deb/DEBIAN/control.in >"${PREFIX}/DEBIAN/control" && \
cd /gsocket-src && \
./configure --prefix="${PREFIX}/usr" --enable-realprefix=/usr && \
make install && \
cd /gsocket-deb/build && \
mv "${PREFIX}/usr/etc" "${PREFIX}" && \
find "$PREFIX" -type d -exec chmod 755 {} \; && \
dpkg-deb --build gsocket_${VER}_all/ && \
dpkg -i "gsocket_${VER}_all.deb" && \
dpkg -r gsocket && \
dpkg -l | grep gsocket || IS_OK=1

[[ -z "$IS_OK" ]] && { echo >&2 "error"; exit 255; }

mv "gsocket_${VER}_all.deb" "/gsocket-pkg/build" || exit 255
echo "SUCCESS."
