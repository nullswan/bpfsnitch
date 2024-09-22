#include "bpf/core.h"

struct syscall_trace_enter_args {
    unsigned long long unused;
    long syscall_nr;
    long arg0;
    long arg1;
    long arg2;
    long arg3;
    long arg4;
    long arg5;
};

SEC("tracepoint/syscalls/sys_enter")
int tracepoint_sys_enter(struct syscall_trace_enter_args *ctx) {
  int syscall_nr = ctx->syscall_nr;

  if (bpf_map_lookup_elem(&syscall_whitelist, &syscall_nr) == NULL) {
    return 0;
  }
  
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  u64 cgroup_id = bpf_get_current_cgroup_id();

  struct syscall_event syscall_event = {
    .syscall_nr = ctx->syscall_nr,
    .cgroup_id = cgroup_id,
    .pid = pid
  };

  bpf_ringbuf_output(&syscall_events_rb, &syscall_event, sizeof(syscall_event), BPF_RB_FORCE_WAKEUP);
  return 0;
}