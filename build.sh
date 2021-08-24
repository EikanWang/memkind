#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (C) 2016 - 2020 Intel Corporation.

set -e

export enable_heap_manager="no"

cd $(dirname $0)
EXTRA_CONF=$@

unset LD_PRELOAD
unset JEMK_MALLOC_CONF
unset MALLOC_CONF
export MEMKIND_PREFIX=""
export MEMTIER_PREFIX=""

# make clean
./autogen.sh
# ./configure --enable-debug-jemalloc $EXTRA_CONF
./configure $EXTRA_CONF

#use V=1 for full cmdlines of build
make all -j`nproc`
#make checkprogs -j`nproc`
