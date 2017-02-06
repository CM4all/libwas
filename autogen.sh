#!/bin/sh

set -e

rm -rf config.cache build
mkdir build
libtoolize --force
aclocal -I m4
automake --add-missing --foreign
autoconf
./configure \
	CFLAGS="-O0 -ggdb" CXXFLAGS="-O0 -ggdb" \
        --prefix=/usr/local/stow/libcm4all-was \
        --enable-debug \
	--enable-silent-rules \
        "$@"
