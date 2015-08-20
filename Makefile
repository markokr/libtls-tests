
AM_CPPFLAGS = -D_GNU_SOURCE=1 -Ilibtls -I/opt/apps/libressl/include
AM_LDFLAGS = -L/opt/apps/libressl/lib
AM_LIBS = -lssl -lcrypto -lrt

tlsfiles = $(wildcard libtls/*.[ch])

noinst_PROGRAMS = connect

connect_SOURCES = connect.c $(tlsfiles)

include $(shell antimake.mk)

