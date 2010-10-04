AUTOMAKE_OPTIONS = foreign 1.10 dist-bzip2

AM_CPPFLAGS += -Iinclude $(LIBHTTP_CFLAGS)
AM_CPPFLAGS += $(GLIB_CFLAGS)

lib_LIBRARIES = src/libcm4all-was-simple.a src/libcm4all-was-apreq.a
src_libcm4all_was_simple_a_SOURCES = src/simple.c
src_libcm4all_was_apreq_a_SOURCES = src/parser.c src/bucket.c
src_libcm4all_was_apreq_a_CPPFLAGS = $(AM_CPPFLAGS) $(LIBAPREQ2_CFLAGS)

wasincludedir = $(includedir)/was
wasinclude_HEADERS = \
	include/was/apreq.h \
	include/was/simple.h \
	include/was/protocol.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcm4all-was-simple.pc libcm4all-was-apreq.pc
