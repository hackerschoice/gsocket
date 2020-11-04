noinst_PROGRAMS = gs-helloworld gs-pipe gs-full-pipe
bin_PROGRAMS = gs-netcat gs_uchroot_so

gs_helloworld_SOURCES = 1_gs-helloworld.c utils.c
gs_helloworld_LDADD = ../lib/libgsocket.a

gs_pipe_SOURCES = 2_gs-pipe.c utils.c
gs_pipe_LDADD = ../lib/libgsocket.a

gs_full_pipe_SOURCES = 3_gs-full-pipe.c utils.c
gs_full_pipe_LDADD = ../lib/libgsocket.a

gs_netcat_SOURCES = 4_gs-netcat.c utils.c socks.c
gs_netcat_LDADD = ../lib/libgsocket.a

dist_bin_SCRIPTS = blitz gs-sftp gs-mount gs_funcs

gs_uchroot_so_SOURCES = gs_uchroot.c
gs_uchroot_so_CFLAGS = -shared -fPIC
gs_uchroot_so_LDFLAGS = -ldl

EXTRA_DIST = run_all_tests.sh
noinst_HEADERS = common.h utils.h socks.h man_gs-netcat.h
CFLAGS += -I../include
