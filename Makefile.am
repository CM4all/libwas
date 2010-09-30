AUTOMAKE_OPTIONS = foreign 1.10 dist-bzip2

AM_CPPFLAGS += -Iinclude $(LIBHTTP_CFLAGS)
AM_CPPFLAGS += $(GLIB_CFLAGS)

lib_LIBRARIES = src/libcm4all-was-simple.a
src_libcm4all_was_simple_a_SOURCES = src/simple.c

wasincludedir = $(includedir)/was
wasinclude_HEADERS = \
	include/was/simple.h \
	include/was/protocol.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcm4all-was-simple.pc
