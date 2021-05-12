FROM debian

ENV OPENSSL_VER=1.1.1k
ENV OPENSSL_ARCH=linux-generic64

RUN apt update -y && \
	apt install -y --no-install-recommends libc6-dev automake gcc make curl ca-certificates && \
	apt clean && \
	rm -rf /var/lib/apt/lists/ && \
	curl https://www.openssl.org/source/openssl-${OPENSSL_VER}.tar.gz \
	| tar -xzC /tmp/ && \
	cd /tmp/openssl-${OPENSSL_VER} && \
	./Configure --prefix=/root/usr no-tests no-dso no-threads no-shared ${OPENSSL_ARCH} && \
	make install_sw && \
	rm -rf rm -rf /tmp/openssl-${OPENSSL_VER} /root/usr/bin/openssl /root/usr/bin/c_rehash && \
	echo done
