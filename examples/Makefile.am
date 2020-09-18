bin_PROGRAMS = gs-helloworld gs-pipe gs-full-pipe gs-netcat
gs_helloworld_SOURCES = 1_gs-helloworld.c utils.c
gs_helloworld_LDADD = ../lib/libgsocket.a

gs_pipe_SOURCES = 2_gs-pipe.c utils.c
gs_pipe_LDADD = ../lib/libgsocket.a

gs_full_pipe_SOURCES = 3_gs-full-pipe.c utils.c
gs_full_pipe_LDADD = ../lib/libgsocket.a

gs_netcat_SOURCES = 4_gs-netcat.c utils.c
gs_netcat_LDADD = ../lib/libgsocket.a

EXTRA_DIST = run_all_tests.sh
noinst_HEADERS = common.h utils.h 
CFLAGS += -I../include
