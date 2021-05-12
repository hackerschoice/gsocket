# test with
# make install DESTDIR=/tmp/installer
noinst_PROGRAMS = gs-helloworld gs-pipe gs-full-pipe @PROGRAMS_TEST_TOOLS@
EXTRA_PROGRAMS = packet-test readline-test console_display-test filetransfer-test
bin_PROGRAMS = gs-netcat
EXTRA_DIST = gsocket.conf.in

noinst_PROGRAMS += gsocket_dso.so.0 gsocket_uchroot_dso.so.0

# https://www.gnu.org/software/automake/manual/automake.html says that
# it should default to '${prefix}/etc' and not '/etc' and that the installer
# will have to set '--sysconfdir=/etc' to change the default behaviour.
gsocket_confdir = $(sysconfdir)
gsocket_conf_DATA = gsocket.conf

gs_funcsdir = $(datarootdir)/gsocket
dist_gs_funcs_DATA = gs_funcs

# lib_LIBRARIES = gsocket_dso.so gsocket_uchroot_dso.so # ERROR: This will generate static libs..
# lib_LTLIBRARIES = gsocket_dso.so gsocket_uchroot_dso.so
# LT_INIT([disable-static]) has no effect. It insists to generate shared
# and static libs (which wont work because those are DSO's on OSX).
# So we must use noinst_PROGRAMS and an install-hook

gs_helloworld_SOURCES = 1_gs-helloworld.c utils.c gsocket_dso-lib.c
gs_helloworld_LDADD = ../lib/libgsocket.a @LDADD_STATIC@
gs_helloworld_CFLAGS = @CFLAGS_STATIC@

gs_pipe_SOURCES = 2_gs-pipe.c utils.c gsocket_dso-lib.c
gs_pipe_LDADD = ../lib/libgsocket.a @LDADD_STATIC@
gs_pipe_CFLAGS = @CFLAGS_STATIC@

gs_full_pipe_SOURCES = 3_gs-full-pipe.c utils.c gsocket_dso-lib.c
gs_full_pipe_LDADD = ../lib/libgsocket.a @LDADD_STATIC@
gs_ful_pipe_CFLAGS = @CFLAGS_STATIC@

gs_netcat_SOURCES = 4_gs-netcat.c utils.c socks.c console.c ids.c event_mgr.c pkt_mgr.c console_display.c filetransfer.c globbing.c filetransfer_mgr.c gsocket_dso-lib.c
gs_netcat_LDADD = ../lib/libgsocket.a @LDADD_STATIC@
gs_netcat_CFLAGS = @CFLAGS_STATIC@

dist_bin_SCRIPTS = blitz gs-sftp gs-mount gsocket

gsocket_uchroot_dso_so_0_SOURCES = gsocket_uchroot_dso.c
gsocket_uchroot_dso_so_0_CFLAGS = -shared -fPIC
gsocket_uchroot_dso_so_0_LDFLAGS = -ldl @SONAME_GSOCKET_UCHROOT_DSO@

gsocket_dso_so_0_SOURCES = gsocket_dso.c gsocket_dso-lib.c
gsocket_dso_so_0_CFLAGS = -shared -fPIC
gsocket_dso_so_0_LDADD = @LDADD_STATIC@
gsocket_dso_so_0_LDFLAGS = -ldl @SONAME_GSOCKET_DSO@

install-exec-hook:
	-rm -f $(DESTDIR)$(bindir)/gs_funcs # Old gs installed this here. Remove it now.
	$(install_sh) -d $(DESTDIR)$(libdir)
	$(install_sh) -c -m @PERM_DSO@ gsocket_dso.so.0 gsocket_uchroot_dso.so.0 $(DESTDIR)$(libdir)
	ln -sf gsocket_dso.so.0$(EXEEXT) $(DESTDIR)$(libdir)/gsocket_dso.so$(EXEEXT)
	ln -sf gsocket_uchroot_dso.so.0$(EXEEXT) $(DESTDIR)$(libdir)/gsocket_uchroot_dso.so$(EXEEXT)

uninstall-hook:
	-rm -f $(DESTDIR)$(libdir)/gsocket_dso.so.0$(EXEEXT)
	-rm -f $(DESTDIR)$(libdir)/gsocket_dso.so$(EXEEXT)
	-rm -f $(DESTDIR)$(libdir)/gsocket_uchroot_dso.so.0$(EXEEXT)
	-rm -f $(DESTDIR)$(libdir)/gsocket_uchroot_dso.so$(EXEEXT)

packet_test_SOURCES = packet-test.c utils.c gsocket_dso-lib.c
packet_test_LDADD = ../lib/libgsocket.a

readline_test_SOURCES = readline-test.c utils.c gsocket_dso-lib.c
readline_test_LDADD = ../lib/libgsocket.a

console_display_test_SOURCES = console_display.c console_display-test.c utils.c gsocket_dso-lib.c
console_display_test_LDADD = ../lib/libgsocket.a

filetransfer_test_SOURCES = filetransfer.c filetransfer-test.c utils.c gsocket_dso-lib.c globbing.c
filetransfer_test_LDADD = ../lib/libgsocket.a

noinst_HEADERS = common.h utils.h socks.h console.h ids.h event_mgr.h pkt_mgr.h gs-netcat.h console_display.h filetransfer.h man_gs-netcat.h globbing.h filetransfer_mgr.h gsocket_dso-lib.h
