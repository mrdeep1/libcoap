#! /bin/sh

# This script creates a libcoap archive, unpacks it and does an
# out-of-tree build and installation afterwards.
#
# Copyright (C) 2021-2026 Olaf Bergmann <bergmann@tzi.org>
#
# This file is part of the CoAP C library libcoap. Please see README
# and COPYING for terms of use.
#

PREFIX=--prefix=`pwd`/libcoap-install
ARCHIVE=`ls -1t libcoap-*.tar.bz2 |head -1`
err=$?
echo $ARCHIVE
if test $err = 0 -a "x$ARCHIVE" != "x"; then
    DIR=`pwd`/`tar taf $ARCHIVE |cut -d/ -f1|head -1`
    tar xaf $ARCHIVE && cd $DIR
    err=$?
    if [ $err != 0 ] ; then
        exit 1
    fi

    # LwIP
    cp -a $RUNNER_TEMP/download/lwip $DIR/examples/lwip
    make -C $DIR/examples/lwip EXTRA_CFLAGS=-Werror
    err=$?
    if [ $err != 0 ] ; then
        exit 1
    fi

    # Contiki
    cp -a $RUNNER_TEMP/download/contiki-ng $DIR/examples/contiki
    (cd $DIR/examples/contiki/contiki-ng/os/net/app-layer && rm -rf libcoap && ln -s ../../../../../.. libcoap)
    make -C $DIR/examples/contiki
    err=$?
    if [ $err != 0 ] ; then
        exit 1
    fi

    # RIOT
    make -C $DIR/examples/riot
    err=$?
    if [ $err != 0 ] ; then
        exit 1
    fi

    # Zephyr
    cp -a $RUNNER_TEMP/download/zephyrproject $DIR/examples/zephyr
    (cd $DIR/examples/zephyr/zephyrproject/zephyr/zephyr-sdk* ; cmake -P cmake/zephyr_sdk_export.cmake)
    make -C $DIR/examples/zephyr EXTRA_CFLAGS=-Werror
    err=$?
    if [ $err != 0 ] ; then
        exit 1
    fi

    # Standard build
    $DIR/configure $PREFIX --enable-tests  --enable-silent-rules --enable-documentation --enable-examples --disable-dtls && \
    make EXTRA_CFLAGS=-Werror && make install EXTRA_CFLAGS=-Werror
    err=$?
    if [ $err != 0 ] ; then
        exit 1
    fi

    # cmake
    cmake -E make_directory test-cmake
    cd test-cmake
    cmake .. -DENABLE_EXAMPLES=ON -DENABLE_TESTS=ON -DENABLE_DTLS=OFF -DENABLE_DOCS=OFF -DWARNING_TO_ERROR=ON
    err=$?
    if [ $err != 0 ] ; then
        exit 1
    fi
fi

exit $err
