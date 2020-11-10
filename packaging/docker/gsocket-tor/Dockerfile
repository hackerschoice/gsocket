FROM hackerschoice/gsocket

COPY bashrc /root/.bashrc

WORKDIR /root/
RUN apt-get update -y \
	&& apt-get install -y --no-install-recommends \
	tor \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/

