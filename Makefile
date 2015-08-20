
COMMON_CPPFLAGS = -D_GNU_SOURCE=1 -Ilibtls

SSL_CPPFLAGS = -I/opt/apps/libressl/include
SSL_LDFLAGS = -L/opt/apps/libressl/lib
SSL_LIBS = -lssl -lcrypto -lrt

tlsfiles = $(wildcard libtls/*.[ch])

noinst_PROGRAMS = connect dotest

connect_SOURCES = connect.c $(tlsfiles)
connect_CPPFLAGS = $(SSL_CPPFLAGS) $(COMMON_CPPFLAGS)
connect_LDFLAGS = $(SSL_LDFLAGS)
connect_LIBS = $(SSL_LIBS)

dotest_SOURCES = tinytest.c tinytest.h tinytest_macros.h test_common.h test_common.c test_tls.c $(tlsfiles)
dotest_CPPFLAGS = $(SSL_CPPFLAGS) $(COMMON_CPPFLAGS)
dotest_LDFLAGS = $(SSL_LDFLAGS)
dotest_LIBS = $(SSL_LIBS) -levent

include $(shell antimake.mk)

