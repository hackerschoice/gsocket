noinst_LIBRARIES = libgsocket.a
noinst_PROGRAMS = list-test event-test
libgsocket_a_SOURCES = gsocket-util.c gsocket-select.c gsocket-sha256.c gsocket-ssl.c gsocket-engine.c packet.c gs-readline.c list.c event.c

list_test_SOURCES = list-test.c
list_test_LDADD = ./libgsocket.a

event_test_SOURCES = event-test.c
event_test_LDADD = ./libgsocket.a

noinst_HEADERS = gsocket-sha256.h gs-common.h gs-externs.h gsocket-engine.h
CFLAGS += -I../include
