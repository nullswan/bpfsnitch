#include "bpf/core.h"

struct tcp_recvmsg_args {
    struct sock *sk;
    struct msghdr *msg;
    size_t len;
    int nonblock;
    int flags;
    int *addr_len;
};

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct tcp_recvmsg_args *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u64 cgroup_id = bpf_get_current_cgroup_id();
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct sock *sk = ctx->sk;
  size_t size = ctx->len;

  __u64 err;
  __be32 saddr, daddr;
  __be16 sport, dport;

  err = bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
  if (err != 0)
    return 0;
  err = bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
  if (err != 0)
    return 0;
  err = bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
  if (err != 0)
    return 0;
  err = bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
  if (err != 0)
    return 0;

  if (is_local_ip(saddr) || is_local_ip(daddr)) {
    return 0;
  }

  struct network_event network_event = {
    .ts = ts,
    .pid = pid,
    .cgroup_id = cgroup_id,
    .saddr = saddr,
    .daddr = daddr,
    .sport = sport,
    .dport = dport,
    .size = size,
    .direction = 0,
    .protocol = 6
  };

  bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, &network_event, sizeof(network_event));
  return 0;
}

struct tcp_sendmsg_args {
    struct sock *sk;
    struct msghdr *msg;
    size_t size;
};

SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct tcp_sendmsg_args *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u64 cgroup_id = bpf_get_current_cgroup_id();
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  struct sock *sk = ctx->sk;
  size_t size = ctx->size;

  __u64 err;
  __be32 saddr, daddr;
  __be16 sport, dport;

  err = bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
  if (err != 0)
    return 0;
  err = bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
  if (err != 0)
    return 0;
  err = bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
  if (err != 0)
    return 0;
  err = bpf_probe_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
  if (err != 0)
    return 0;

  if (is_local_ip(saddr) || is_local_ip(daddr)) {
      return 0;
  }

  struct network_event network_event = {
    .ts = ts,
    .pid = pid,
    .cgroup_id = cgroup_id,
    .saddr = saddr,
    .daddr = daddr,
    .sport = sport,
    .dport = dport,
    .size = size,
    .direction = 1,
    .protocol = 6
  };

  bpf_perf_event_output(ctx, &network_events, BPF_F_CURRENT_CPU, &network_event, sizeof(network_event));
  return 0;
}
