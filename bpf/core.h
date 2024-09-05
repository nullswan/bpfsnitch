#include "vmlinux.h"

#include <linux/version.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, 0);
  __uint(max_entries, 1024);
} syscall_whitelist SEC(".maps");

struct syscall_event {
  long syscall_nr;
  u64 ts;
  u64 user_id;
  u64 cgroup_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 1024);
} syscall_events SEC(".maps");