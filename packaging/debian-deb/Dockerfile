# Debian: :stable still runs on openssl-1.1.0 and but kali and most debian
# derived need openssl3.
FROM debian:sid


RUN apt update -y && \
	apt install -y --no-install-recommends git sshfs libssl-dev libc6-dev automake gcc make curl ca-certificates && \
	apt clean && \
	rm -rf /var/lib/apt/lists/ && \
	echo done
