#include "bpf/core.h"

struct udp_recvmsg_args {
    struct sock *sk;
    struct msghdr *msg;
    size_t size;
    int flags;
    int *addr_len;
};

SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct udp_recvmsg_args *ctx) {
  u64 cgroup_id = bpf_get_current_cgroup_id();
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct sock *sk = ctx->sk;
  size_t size = ctx->size;

  __u64 err;
  __be32 saddr;
	__be32 daddr;
	__be16 dport;
	__u16 sport;

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
  
  struct network_event e = {};
  e.pid = pid;
  e.cgroup_id = cgroup_id;
  e.saddr = saddr;
  e.daddr = daddr;
  e.sport = sport;
  e.dport = dport;
  e.size = size;
  e.direction = DIRECTION_INBOUND;
  e.protocol = PROTOCOL_UDP;

  bpf_ringbuf_output(&network_events_rb, &e, sizeof(e), BPF_RB_FORCE_WAKEUP);
  return 0;
}

struct udp_sendmsg_args {
    struct sock *sk;
    struct msghdr *msg;
    size_t len;
};

SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct udp_sendmsg_args *ctx) {
  u64 cgroup_id = bpf_get_current_cgroup_id();
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  struct sock *sk = ctx->sk;
  size_t size = ctx->len;

  __u64 err;
  __be32 saddr;
  __be32 daddr;
  __be16 sport;
  __be16 dport;

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

  struct network_event e = {};
  e.direction = DIRECTION_OUTBOUND;
  e.protocol = PROTOCOL_UDP;
  e.pid = pid;
  e.cgroup_id = cgroup_id;
  e.saddr = saddr;
  e.daddr = daddr;
  e.sport = sport;
  e.dport = dport;

  bpf_ringbuf_output(&network_events_rb, &e, sizeof(e), BPF_RB_FORCE_WAKEUP);
  return 0;
}