#!/bin/bash
set -e

SOURCE_FILE=bpf/main.c
LIBNAME=bpfsnitch_lib
CFLAGS="-g -O2 -target bpf"

if [ -n "$DEBUG" ]; then
  CFLAGS="$CFLAGS -DDEBUG"
fi

if [ -z "$TARGETARCH" ]; then
  echo "TARGETARCH is not set"
  exit 1
fi

case "$TARGETARCH" in
  "amd64")
    ARCH_FLAGS="-D__TARGET_ARCH_x86"
    OUTPUT_FILE="${LIBNAME}_amd64.o"
    ;;
  "arm64")
    ARCH_FLAGS="-D__TARGET_ARCH_arm64"
    OUTPUT_FILE="${LIBNAME}_arm64.o"
    ;;
  "arm")
    ARCH_FLAGS="-D__TARGET_ARCH_arm"
    OUTPUT_FILE="${LIBNAME}_arm.o"
    ;;
  "386")
    ARCH_FLAGS="-D__TARGET_ARCH_x86"
    OUTPUT_FILE="${LIBNAME}_x86.o"
    ;;
  *)
    echo "Unknown architecture: `$TARGETARCH`"
    exit 1
    ;;
esac

clang $CFLAGS $ARCH_FLAGS -c $SOURCE_FILE -o $OUTPUT_FILE -I.
