FROM kalilinux/kali-rolling

# Must be debian compiled binaries:
COPY gsocket_latest_all.deb /tmp
COPY gs-motd /etc/
COPY bashrc /tmp

WORKDIR /root/
RUN apt update -y && \
	apt install -y --no-install-recommends \
	vim \
	binutils \
	openssl \
	rsync \
	openssh-server \
	sshfs && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/ && \
	dpkg -i /tmp/gsocket_latest_all.deb && \
	cat /tmp/bashrc >>/root/.bashrc
