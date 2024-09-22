# bpfsnitch

[![License: GPL](https://img.shields.io/badge/License-GPL-blue.svg)](LICENSE) [![Go Report Card](https://goreportcard.com/badge/github.com/nullswan/bpfsnitch)](https://goreportcard.com/report/github.com/nullswan/bpfsnitch)

bpfsnitch is an open-source, real-time monitoring tool for Linux systems and Kubernetes clusters. Inspired by GlassWire, bpfsnitch leverages eBPF (extended Berkeley Packet Filter) technology to provide observability at the lowest level possible by tracking system calls and network activities. It is capable of monitoring every syscall and network event in real-time, offering valuable insights into what's happening inside your systems and containers.

---

## Table of Contents

- [bpfsnitch](#bpfsnitch)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
    - [On Kubernetes Clusters](#on-kubernetes-clusters)
  - [Metrics](#metrics)
    - [Key Metrics](#key-metrics)
    - [Example Metrics Output](#example-metrics-output)
  - [Performance](#performance)
  - [Configuration (soon)](#configuration-soon)
    - [Customizing Syscall Monitoring](#customizing-syscall-monitoring)
      - [Predefined Syscalls](#predefined-syscalls)
  - [Educational Value](#educational-value)
  - [License](#license)
  - [Future Plans](#future-plans)
  - [Contact](#contact)
  - [Acknowledgments](#acknowledgments)
  - [Join the Community](#join-the-community)

---

## Features

- **Real-Time Monitoring**: Track every syscall and network event as they happen.
- **eBPF Powered**: Utilizes eBPF for efficient, low-overhead monitoring at the kernel level.
- **Kubernetes Support**: Deployable as a DaemonSet to monitor your entire Kubernetes cluster.
- **Customizable Syscall Monitoring**: Predefined list of critical syscalls with plans to provide a configurable syscall whitelist.
- **Prometheus Integration**: Exposes metrics via a Prometheus scrape endpoint for easy integration with your monitoring stack.
- **Pod Awareness**: Labels metrics with pod names for granular visibility.
- **Open Source**: Released under the GPL license, encouraging community collaboration.

---

## Prerequisites

- **Linux Kernel with eBPF Support**: bpfsnitch requires a Linux kernel version that supports eBPF (version 5.8 or higher recommended).
- **eBPF Libraries**: Ensure that `libbpf` and related dependencies are installed.
- **Prometheus**: For metrics scraping and monitoring.
- **Container Runtime**: Supports Docker and Containerd Kubernetes environments.

---

## Installation

### On Kubernetes Clusters

Deploy bpfsnitch as a DaemonSet to monitor all nodes in your cluster.

1. Apply the DaemonSet Manifest

```bash
curl -s https://raw.githubusercontent.com/nullswan/bpfsnitch/main/deployments/daemonset.yaml | kubectl apply -f -
```

## Metrics

bpfsnitch exposes a variety of Prometheus metrics, providing insights into syscalls and network activities.

### Key Metrics

- Syscall Counters: Counts of specific syscalls made by processes or pods.
- Network Bytes Counters: Total bytes sent and received, labeled by pod and remote subnets.
- Network Packets Counters: Total packets sent and received.
- DNS Query Counters: Number of DNS queries made by pods.

### Example Metrics Output

```perl
# HELP bpfsnitch_dns_query_counter Number of DNS queries
# TYPE bpfsnitch_dns_query_counter counter
bpfsnitch_dns_query_counter{container="kube-proxy-cwn8r"} 23

# HELP bpfsnitch_network_received_bytes_counter Number of bytes received
# TYPE bpfsnitch_network_received_bytes_counter counter
bpfsnitch_network_received_bytes_counter{pod="nginx-7b9f54988c-2tpbd",remote_subnet="0.0.0.0/24"} 1334512

# HELP bpfsnitch_network_received_packets_counter Number of packets received
# TYPE bpfsnitch_network_received_packets_counter counter
bpfsnitch_network_received_packets_counter{pod="nginx-7b9f54988c-2tpbd",remote_subnet="0.0.0.0/24"} 623

# HELP bpfsnitch_network_sent_bytes_counter Number of bytes sent
# TYPE bpfsnitch_network_sent_bytes_counter counter
bpfsnitch_network_sent_packets_counter{pod="kube-proxy-cwn8r",remote_subnet="1.2.3.0/24"} 1293500
bpfsnitch_network_sent_packets_counter{pod="kube-proxy-cwn8r",remote_subnet="1.2.97.0/24"} 80
bpfsnitch_network_sent_packets_counter{pod="kube-proxy-cwn8r",remote_subnet="1.2.111.0/24"} 310
bpfsnitch_network_sent_packets_counter{pod="kube-proxy-cwn8r",remote_subnet="1.2.108.0/24"} 65

# HELP bpfsnitch_network_sent_packets_counter Number of packets sent
# TYPE bpfsnitch_network_sent_packets_counter counter
bpfsnitch_network_sent_packets_counter{pod="kube-proxy-cwn8r",remote_subnet="1.2.3.0/24"} 1529
bpfsnitch_network_sent_packets_counter{pod="kube-proxy-cwn8r",remote_subnet="1.2.97.0/24"} 1
bpfsnitch_network_sent_packets_counter{pod="kube-proxy-cwn8r",remote_subnet="1.2.111.0/24"} 3
bpfsnitch_network_sent_packets_counter{pod="kube-proxy-cwn8r",remote_subnet="1.2.108.0/24"} 1

# HELP bpfsnitch_syscall_counter Number of syscalls
# TYPE bpfsnitch_syscall_counter counter
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="arch_prctl"} 520
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="bind"} 2713
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="clone"} 818
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="connect"} 264
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="getrandom"} 578
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="getsockname"} 2845
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="read"} 16424
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="recvmsg"} 56939
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="sendmsg"} 443
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="sendto"} 32007
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="setsockopt"} 819
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="socket"} 2845
bpfsnitch_syscall_counter{pod="kube-proxy-cwn8r",syscall="wait4"} 818
```

## Performance

Starting from v0.1.0, bpfsnitch is built to be lightweight and efficient using eBPF technology. It monitors syscalls and network events at the kernel level, providing real-time insights with minimal system impact.

In production, bpfsnitch typically uses an average of 5ms of CPU per 60-second scrape and maintains a memory footprint of up to `250MB`. It is statically bound to a maximum of `100ms` CPU usage, ensuring consistent performance regardless of system configuration or workload. See the [DaemonSet resources](https://github.com/search?q=repo%3Anullswan/bpfsnitch%20resources&type=code)

To monitor bpfsnitch's performance in real-time, start it with the -pprof flag to expose a pprof server. Access live profiling data at the /debug/pprof route to analyze CPU and memory usage and optimize performance as needed.

We are committed to providing detailed performance benchmarks and optimization tips in future releases to help you maximize bpfsnitch's benefits.

## Configuration (soon)

### Customizing Syscall Monitoring

bpfsnitch comes with a predefined list of syscalls to monitor, focusing on critical operations that could affect system security or stability. We plan to provide a configurable syscall whitelist in future releases, allowing you to tailor monitoring to your specific needs.

#### Predefined Syscalls

```go
var WhitelistedSyscalls = []int{
    SyscallToId["clone"],
    SyscallToId["execve"],
    SyscallToId["mknodat"],
    SyscallToId["chroot"],
    SyscallToId["mount"],
    SyscallToId["umount2"],
    SyscallToId["pivot_root"],
    SyscallToId["setuid"],
    SyscallToId["setgid"],
    ...
```

## Educational Value

bpfsnitch is not only a powerful monitoring tool but also an excellent educational resource. It provides insights into:
- eBPF Programming: Learn how eBPF programs are written and attached to kernel functions.
- System Call Mechanics: Understand how syscalls work and how they impact system behavior.
- Kernel-Level Monitoring: Gain knowledge about low-level monitoring techniques in Linux.
- Observability Practices: Explore how to collect and expose metrics for modern monitoring systems like Prometheus.

## License

bpfsnitch is released under the GNU General Public License (GPL).

## Future Plans

- Configurable Syscall Whitelist: Allow users to define which syscalls to monitor.
- User Interface: Develop a web-based UI for easier visualization and management.
- Performance Optimizations: Enhance the efficiency of data collection and processing.
- Additional Metrics: Include more granular metrics, such as latency measurements and error counts.
- Extended Container Support: Improve compatibility with various container runtimes and orchestration platforms.

## Contact

- Contributor: [@nullswan](https://github.com/nullswan) <pro@nullswan.io>
- Reviewers: [@gmarcha](https://github.com/gmarcha), [@naofel1](https://github.com/naofel1)
- GitHub Issues: [https://github.com/nullswan/bpfsnitch/issues](https://github.com/nullswan/bpfsnitch/issues)

## Acknowledgments

- eBPF Community: For providing extensive resources and support for eBPF development.
- Prometheus: For their powerful monitoring and alerting toolkit.
- Open Source Community: Thanks to all who have contributed to the open-source ecosystem, making projects like bpfsnitch possible.

## Join the Community

If you find bpfsnitch valuable, please give us a ⭐ star on GitHub and share it with others who might be interested. Your support helps us improve and grow the project!

Feel free to reach out if you have any questions or need assistance getting started with bpfsnitch. We look forward to your feedback!
