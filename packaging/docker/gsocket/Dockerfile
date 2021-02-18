FROM debian

# Must be debian compiled binaries:
COPY gs-netcat gs-sftp gs-mount blitz gs_funcs gs_uchroot_so /usr/local/bin/
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
