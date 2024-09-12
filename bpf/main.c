//go:build exclude

#include "tracepoint/trace_syscall.c"

char _license[] SEC("license") = "GPL";
#define KBUILD_MODNAME "bpfsnitch"