# $FreeBSD$

PORTNAME=		gsocket
DISTVERSION=	1.4.22
CATEGORIES=		net
LICENSE=		BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

MAINTAINER=		someone@somewhere.sometld
COMMENT=		Global Socket allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.

USE_GITHUB=		yes
GH_ACCOUNT=		hackerschoice
GH_PROJECT=		gsocket
GH_TAGNAME=		v1.4.22
GH_TUPLE=		hackerschoice:gsocket:v1.4.22

# used in the bootstrap script
BUILD_DEPENDS=	autoconf:devel/autoconf \
				autoheader:devel/autoconf \
				aclocal:devel/automake \
				automake:devel/automake

USES=	fakeroot shebangfix ssl 

INSTALL_TARGET=	install-strip

PLIST_FILES=	bin/blitz \
				bin/gs-netcat \
				bin/gs_uchroot_so \
				bin/gs-sftp \
				bin/gs-mount \
				bin/gs_funcs \
				share/man/man1/blitz.1.gz \
				share/man/man1/gs-mount.1.gz \
				share/man/man1/gs-netcat.1.gz \
				share/man/man1/gs-sftp.1.gz \
				share/licenses/gsocket-1.4.22/catalog.mk \
				share/licenses/gsocket-1.4.22/LICENSE \
				share/licenses/gsocket-1.4.22/BSD2CLAUSE


pre-configure:
	v=`pwd`
	cd ${WRKSRC} && ./bootstrap && ./configure && cd ${v}

.include <bsd.port.mk>
