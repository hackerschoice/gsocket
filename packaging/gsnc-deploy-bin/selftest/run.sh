#! /bin/sh

BASEDIR="$(cd "$(dirname "${0}")" || exit; pwd)"

# IF this is not a live test then use local binaries (GS_DEBUG=1)
if [[ -z $GS_LIVE ]]; then
	export GS_DEBUG=1
	${BASEDIR}/deploy.sh && \
	GS_UNDO=1 ${BASEDIR}/deploy.sh
else
	echo "Running LIVE test..."
	{ command -v curl >/dev/null && bash -c "$(curl -fsSL gsocket.io/x)" || bash -c "$(wget -qO- gsocket.io/x)"; } && \
	export GS_UNDO=1 && \
	{ command -v curl >/dev/null && bash -c "$(curl -fsSL gsocket.io/x)" || bash -c "$(wget -qO- gsocket.io/x)"; }
fi
