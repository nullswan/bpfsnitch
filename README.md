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
- **Container Awareness**: Labels metrics with container names for granular visibility.
- **Open Source**: Released under the GPL license, encouraging community collaboration.

---

## Prerequisites

- **Linux Kernel with eBPF Support**: bpfsnitch requires a Linux kernel version that supports eBPF (version 4.4 or higher recommended).
- **eBPF Libraries**: Ensure that `libbpf` and related dependencies are installed.
- **Prometheus**: For metrics scraping and monitoring.
- **Container Runtime**: Supports Docker and Kubernetes environments.

---

## Installation

### On Kubernetes Clusters

Deploy bpfsnitch as a DaemonSet to monitor all nodes in your cluster.

1. Apply the DaemonSet Manifest

```bash
kubectl apply -f kubernetes/bpfsnitch-daemonset.yaml
```

## Metrics

bpfsnitch exposes a variety of Prometheus metrics, providing insights into syscalls and network activities.

### Key Metrics

- Syscall Counters: Counts of specific syscalls made by processes or containers.
- Network Bytes Counters: Total bytes sent and received, labeled by container and remote IP.
- Network Packets Counters: Total packets sent and received.
- DNS Query Counters: Number of DNS queries made by containers.

### Example Metrics Output

```perl
# HELP dns_query_counter Number of DNS queries
# TYPE dns_query_counter counter
dns_query_counter{container="alpine-sandbox"} 23

# HELP network_received_bytes_counter Number of bytes received
# TYPE network_received_bytes_counter counter
network_received_bytes_counter{container="alpine-sandbox",remote_ip="127.0.0.53"} 492
network_received_bytes_counter{container="alpine-sandbox",remote_ip="142.250.179.110"} 2529
network_received_bytes_counter{container="alpine-sandbox",remote_ip="172.217.20.164"} 2541

# HELP network_received_packets_counter Number of packets received
# TYPE network_received_packets_counter counter
network_received_packets_counter{container="alpine-sandbox",remote_ip="127.0.0.53"} 12
network_received_packets_counter{container="alpine-sandbox",remote_ip="142.250.179.110"} 21
network_received_packets_counter{container="alpine-sandbox",remote_ip="172.217.20.164"} 21

# HELP network_sent_bytes_counter Number of bytes sent
# TYPE network_sent_bytes_counter counter
network_sent_bytes_counter{container="alpine-sandbox",remote_ip="127.0.0.53"} 94231
network_sent_bytes_counter{container="alpine-sandbox",remote_ip="142.250.179.110"} 24160
network_sent_bytes_counter{container="alpine-sandbox",remote_ip="172.217.20.164"} 81794

# HELP network_sent_packets_counter Number of packets sent
# TYPE network_sent_packets_counter counter
network_sent_packets_counter{container="alpine-sandbox",remote_ip="127.0.0.53"} 23
network_sent_packets_counter{container="alpine-sandbox",remote_ip="142.250.179.110"} 80
network_sent_packets_counter{container="alpine-sandbox",remote_ip="172.217.20.164"} 167

# HELP syscall_counter Number of syscalls
# TYPE syscall_counter counter
syscall_counter{container="alpine-sandbox",syscall="clone"} 3
syscall_counter{container="alpine-sandbox",syscall="connect"} 28
syscall_counter{container="alpine-sandbox",syscall="execve"} 3
syscall_counter{container="alpine-sandbox",syscall="getsockopt"} 6
syscall_counter{container="alpine-sandbox",syscall="recvfrom"} 270
syscall_counter{container="alpine-sandbox",syscall="sendto"} 54
syscall_counter{container="alpine-sandbox",syscall="setsockopt"} 30
syscall_counter{container="alpine-sandbox",syscall="socket"} 31
syscall_counter{container="alpine-sandbox",syscall="wait4"} 6
```

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
