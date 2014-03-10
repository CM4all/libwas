#!/bin/sh

set -e

rm -rf config.cache build
mkdir build
aclocal -I m4
automake --add-missing --foreign
autoconf
CFLAGS="-O0 -ggdb" ./configure \
        --prefix=/usr/local/stow/libcm4all-was \
        --enable-debug \
	--enable-silent-rules \
        "$@"
