//go:build exclude

#include "kprobe/syscall_trace_enter.c"

char _license[] SEC("license") = "GPL";
#define KBUILD_MODNAME "bpfsnitch"