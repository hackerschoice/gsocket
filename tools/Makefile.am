noinst_PROGRAMS = gs-helloworld gs-pipe gs-full-pipe @PROGRAMS_TEST_TOOLS@
EXTRA_PROGRAMS = packet-test readline-test console_display-test filetransfer-test
bin_PROGRAMS = gs-netcat gs_uchroot_so

gs_helloworld_SOURCES = 1_gs-helloworld.c utils.c
gs_helloworld_LDADD = ../lib/libgsocket.a

gs_pipe_SOURCES = 2_gs-pipe.c utils.c
gs_pipe_LDADD = ../lib/libgsocket.a

gs_full_pipe_SOURCES = 3_gs-full-pipe.c utils.c
gs_full_pipe_LDADD = ../lib/libgsocket.a

gs_netcat_SOURCES = 4_gs-netcat.c utils.c socks.c console.c ids.c event_mgr.c pkt_mgr.c console_display.c filetransfer.c globbing.c
gs_netcat_LDADD = ../lib/libgsocket.a

dist_bin_SCRIPTS = blitz gs-sftp gs-mount gs_funcs

gs_uchroot_so_SOURCES = gs_uchroot.c
gs_uchroot_so_CFLAGS = -shared -fPIC
gs_uchroot_so_LDFLAGS = -ldl

packet_test_SOURCES = packet-test.c utils.c
packet_test_LDADD = ../lib/libgsocket.a

readline_test_SOURCES = readline-test.c utils.c
readline_test_LDADD = ../lib/libgsocket.a

console_display_test_SOURCES = console_display.c console_display-test.c utils.c
console_display_test_LDADD = ../lib/libgsocket.a

filetransfer_test_SOURCES = filetransfer.c filetransfer-test.c utils.c globbing.c
filetransfer_test_LDADD = ../lib/libgsocket.a

EXTRA_DIST = run_all_tests.sh
noinst_HEADERS = common.h utils.h socks.h console.h ids.h event_mgr.h pkt_mgr.h gs-netcat.h console_display.h filetransfer.h man_gs-netcat.h globbing.h
AM_CFLAGS = -I../include
