FROM hackerschoice/gsocket

WORKDIR /root/
RUN apt-get update -y \
	&& apt-get install -y --no-install-recommends \
	tor \
	&& touch /root/.gs_with_tor \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/

