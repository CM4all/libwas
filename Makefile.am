AUTOMAKE_OPTIONS = foreign 1.10 dist-bzip2 subdir-objects

AM_CPPFLAGS += -Iinclude $(LIBHTTP_CFLAGS)
AM_CPPFLAGS += $(GLIB_CFLAGS)

lib_LIBRARIES = \
	src/libcm4all-was-simple.a \
	src/libcm4all-was-apreq.a \
	src/libcm4all-was-xios.a
src_libcm4all_was_simple_a_SOURCES = src/simple.c
src_libcm4all_was_apreq_a_SOURCES = src/parser.c src/bucket.c
src_libcm4all_was_apreq_a_CPPFLAGS = $(AM_CPPFLAGS) $(LIBAPREQ2_CFLAGS)
src_libcm4all_was_xios_a_SOURCES = src/istub.c src/ostub.c
src_libcm4all_was_xios_a_CPPFLAGS = $(AM_CPPFLAGS) $(LIBCORE_CFLAGS)

wasincludedir = $(includedir)/was
wasinclude_HEADERS = \
	include/was/istub.h include/was/ostub.h \
	include/was/apreq.h \
	include/was/simple.h \
	include/was/protocol.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = \
	libcm4all-was-simple.pc \
	libcm4all-was-apreq.pc \
	libcm4all-was-xios.pc
