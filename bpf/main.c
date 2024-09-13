//go:build exclude

#include "tracepoint/trace_syscall.c"
#include "kprobe/trace_udp.c"
#include "kprobe/trace_tcp.c"

static inline int is_local_ip(__be32 ip) {
  // Check for 127.0.0.0/8
  if ((ip & 0xFF000000) == 0x7F000000) {
    return 1;
  }

  // Check for 10.0.0.0/8
  if ((ip & 0xFF000000) == 0x0A000000) {
    return 1;
  }

  // Check for 172.16.0.0/12
  if ((ip & 0xFFF00000) == 0xAC100000) {
    return 1;
  }

  // Check for 192.168.0.0/16
  if ((ip & 0xFFFF0000) == 0xC0A80000) {
    return 1;
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
#define KBUILD_MODNAME "bpfsnitch"