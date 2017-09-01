ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = foreign 1.11 subdir-objects

AM_CPPFLAGS += -Iinclude $(LIBHTTP_CFLAGS)

lib_LTLIBRARIES = \
	libcm4all-was-simple.la \
	libcm4all-was-apreq.la \
	libcm4all-was-xios.la

libcm4all_was_simple_la_SOURCES = \
	src/iterator.cxx src/iterator.hxx \
	src/simple.cxx
libcm4all_was_simple_la_CPPFLAGS = $(AM_CPPFLAGS) \
	$(LIBCM4ALL_INLINE_CFLAGS)
libcm4all_was_simple_la_LDFLAGS = \
	-no-undefined \
	-Wl,--version-script=$(srcdir)/libcm4all-was-simple.ld \
	-version-info $(LIBWAS_LIBTOOL_VERSION)

libcm4all_was_apreq_la_SOURCES = src/parser.c src/bucket.c
libcm4all_was_apreq_la_CPPFLAGS = $(AM_CPPFLAGS) \
	$(LIBAPR_CFLAGS) $(LIBAPR_UTIL_CFLAGS) $(LIBAPREQ2_CFLAGS) \
	$(LIBCM4ALL_INLINE_CFLAGS)
libcm4all_was_apreq_la_LDFLAGS = \
	-no-undefined \
	$(LIBAPR_LIBS) $(LIBAPR_UTIL_LIBS) $(LIBAPREQ2_LIBS) \
	-Wl,--version-script=$(srcdir)/libcm4all-was-apreq.ld \
	-version-info $(LIBWAS_LIBTOOL_VERSION)
libcm4all_was_apreq_la_LIBADD = libcm4all-was-simple.la

libcm4all_was_xios_la_SOURCES = src/istub.c src/ostub.c
libcm4all_was_xios_la_CPPFLAGS = $(AM_CPPFLAGS) \
	$(LIBCORE_CFLAGS) \
	$(LIBCM4ALL_INLINE_CFLAGS)
libcm4all_was_xios_la_LDFLAGS = \
	-no-undefined \
	$(LIBCORE_LIBS) \
	-Wl,--version-script=$(srcdir)/libcm4all-was-xios.ld \
	-version-info $(LIBWAS_LIBTOOL_VERSION)
libcm4all_was_xios_la_LIBADD = libcm4all-was-simple.la

wasincludedir = $(includedir)/was
wasinclude_HEADERS = \
	include/was/istub.h include/was/ostub.h \
	include/was/apreq.h \
	include/was/simple.h \
	include/was/protocol.h

pkgconfigdir = $(datadir)/pkgconfig
pkgconfig_DATA = \
	libcm4all-was-protocol.pc

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = \
	libcm4all-was-simple.pc \
	libcm4all-was-apreq.pc \
	libcm4all-was-xios.pc

# Examples

wasdir = $(pkglibdir)/was-bin
was_PROGRAMS = \
	hello \
	random \
	mirror

hello_SOURCES = examples/hello.c
hello_LDADD = libcm4all-was-simple.la
hello_LDFLAGS = $(AM_LDFLAGS) $(LIBHTTP_LIBS)
hello_CPPFLAGS = $(AM_CPPFLAGS) $(LIBCM4ALL_INLINE_CFLAGS)

random_SOURCES = examples/random.c
random_LDADD = libcm4all-was-simple.la
random_LDFLAGS = $(AM_LDFLAGS) $(LIBHTTP_LIBS)
random_CPPFLAGS = $(AM_CPPFLAGS) $(LIBCM4ALL_INLINE_CFLAGS)

mirror_SOURCES = examples/mirror.c
mirror_LDADD = libcm4all-was-simple.la
mirror_LDFLAGS = $(AM_LDFLAGS) $(LIBHTTP_LIBS)
mirror_CPPFLAGS = $(AM_CPPFLAGS) $(LIBCM4ALL_INLINE_CFLAGS)

# Documentation

doc/_build/html/index.html: doc/index.rst
	cd doc && sphinx-build -q -b html -d _build/doctrees $(abs_srcdir)/doc _build/html

clean-local:
	rm -rf doc/_build
