#pragma once
#include "vmlinux.h"

#include <linux/version.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

static inline int is_local_ip(__be32 ip);

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, 0);
  __uint(max_entries, 1024);
} syscall_whitelist SEC(".maps");

struct syscall_event {
  long syscall_nr;
  u64 cgroup_id;
  u64 pid;
};

struct network_event {
  u64 pid;
  u64 cgroup_id;
  u64 size;

  u32 saddr;
  u32 daddr;
  
  u16 sport;
  u16 dport;

  u8 direction;
  u8 protocol;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1<<25); // 32MB
} network_events_rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1<<24); // 16MB
} syscall_events_rb SEC(".maps");
