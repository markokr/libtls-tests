
#WFLAGS = -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
WFLAGS = -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wmissing-prototypes -Wpointer-arith -Wendif-labels -Wdeclaration-after-statement -Wold-style-definition -Wstrict-prototypes -Wundef -Wformat=2 -Wuninitialized
#WFLAGS += -Wno-pointer-sign -Wno-sign-compare

ifeq ($(shell uname -s), Linux)
EXTRA_CPPFLAGS = -Icompat
EXTRA_LIBS = -lrt
endif

COMMON_CPPFLAGS = -D_GNU_SOURCE=1 -Ilibtls $(EXTRA_CPPFLAGS)

SSL_CPPFLAGS = -I/opt/apps/libressl/include
SSL_LDFLAGS = -L/opt/apps/libressl/lib
SSL_LIBS = -lssl -lcrypto $(EXTRA_LIBS)

noinst_PROGRAMS = connect dotest xparse
noinst_LIBRARIES = libtls.a

libtls_a_SOURCES = $(wildcard libtls/*.[ch])
libtls_a_CPPFLAGS = $(COMMON_CPPFLAGS) $(SSL_CPPFLAGS)

connect_SOURCES = connect.c
connect_CPPFLAGS = $(COMMON_CPPFLAGS)
connect_LDFLAGS = $(SSL_LDFLAGS)
connect_LDADD = libtls.a
connect_LIBS = $(SSL_LIBS)

dotest_SOURCES = tinytest.c tinytest.h tinytest_macros.h test_common.h test_common.c test_tls.c
dotest_CPPFLAGS = $(COMMON_CPPFLAGS) $(SSL_CPPFLAGS)
dotest_LDFLAGS = $(SSL_LDFLAGS)
dotest_LDADD = libtls.a
dotest_LIBS = $(SSL_LIBS) -levent


xparse_SOURCES = parse_x509.c mbuf.c
xparse_CPPFLAGS = $(COMMON_CPPFLAGS) -I.
xparse_LDFLAGS = $(SSL_LDFLAGS)
xparse_LDADD = libtls.a
xparse_LIBS = $(SSL_LIBS) -lz

include antimake.mk

