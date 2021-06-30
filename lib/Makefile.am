noinst_LIBRARIES = libgsocket.a
noinst_PROGRAMS = @PROGRAMS_TEST_LIB@
EXTRA_PROGRAMS = list-test event-test

libgsocket_a_SOURCES = gsocket-util.c gsocket-select.c gsocket-ssl.c gsocket-engine.c packet.c gs-readline.c list.c event.c buf.c

list_test_SOURCES = list-test.c
list_test_LDADD = libgsocket.a

event_test_SOURCES = event-test.c
event_test_LDADD = libgsocket.a

noinst_HEADERS = gs-common.h gs-externs.h gsocket-engine.h
