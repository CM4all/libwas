#!/bin/sh -e
rm -rf build
exec meson . output/debug -Dprefix=/usr/local/stow/libcm4all-was --werror "$@"
