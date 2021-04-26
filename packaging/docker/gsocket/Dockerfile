FROM debian

# Must be debian compiled binaries:
COPY gsocket gs-netcat gs-sftp gs-mount blitz /usr/local/bin/
RUN mkdir -p /usr/local/share/gsocket
COPY gsocket.conf /etc/
COPY gs_funcs /usr/local/share/gsocket
COPY gsocket_uchroot_dso.so.0 gsocket_dso.so.0 /usr/local/lib/
COPY gs-motd /etc/
COPY bashrc /root/.bashrc

WORKDIR /root/
RUN apt-get update -y \
	&& apt-get install -y --no-install-recommends \
	binutils \
	openssl \
	rsync \
	openssh-server \
	sshfs \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/
