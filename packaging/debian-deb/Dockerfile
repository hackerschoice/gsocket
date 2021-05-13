FROM debian

ENV OPENSSL_VER=1.1.1k
ENV OPENSSL_ARCH=linux-generic64

RUN apt update -y && \
	apt install -y --no-install-recommends git sshfs libssl-dev libc6-dev automake gcc make curl ca-certificates && \
	apt clean && \
	rm -rf /var/lib/apt/lists/ && \
	echo done
