FROM alpine

ENV OPENSSL_VER=1.1.1w
ENV OPENSSL_ARCH=linux-generic64

WORKDIR /root/
RUN apk update \
	&& apk add --no-cache bash musl-dev linux-headers gcc make automake openssl-dev curl upx && \
	rm -rf /var/cache/apk/* && \
	curl https://www.openssl.org/source/openssl-${OPENSSL_VER:-1.1.1w}.tar.gz \
	| tar -xzC /tmp/ && \
	cd /tmp/openssl-${OPENSSL_VER:-1.1.1w} && \
	./Configure --prefix=/root/usr no-tests no-dso no-threads no-shared ${OPENSSL_ARCH:-linux-generic64} && \
	make install_sw && \
	rm -rf rm -rf /tmp/openssl-${OPENSSL_VER:-1.1.1w} /root/usr/bin/openssl /root/usr/bin/c_rehash && \
	echo done
