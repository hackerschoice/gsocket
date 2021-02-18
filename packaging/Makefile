
VERSION=1.4.23
BIN_NAME=gsocket
PKG_NAME=${BIN_NAME}-${VERSION}

debuild-setup: ../${PKG_NAME}.tar.gz
	rm -rf build
	mkdir build
	cp ../${PKG_NAME}.tar.gz build && \
	cd build && \
	tar xfz ${PKG_NAME}.tar.gz
	-cd build/${PKG_NAME} && \
	dh_make -sy -f ../${PKG_NAME}.tar.gz && \
	rm -f debian/*.EX debian/*.ex debian/*.docs debian/README.* && \
	cp -a ../../debian/* debian/ && \
	uscan . 

debian-debuild: debuild-setup
	cd build/${PKG_NAME} && \
	debuild -S
	lintian --pedantic -IE build/${BIN_NAME}_*.dsc

clean:
	rm -rf ./build ./${PKG_NAME}.tar.gz

debian: debian-debuild
	echo Done.

