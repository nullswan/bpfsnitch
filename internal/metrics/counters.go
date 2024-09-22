package metrics

import "github.com/prometheus/client_golang/prometheus"

var DNSQueryCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "dns_query_counter",
		Help: "Number of DNS queries",
	},
	[]string{"pod"},
)

var SyscallCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "syscall_counter",
		Help: "Number of syscalls",
	},
	[]string{"syscall", "pod"},
)

var NetworkReceivedBytesCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_received_bytes_counter",
		Help: "Number of bytes received",
	},
	[]string{"pod", "remote_subnet"},
)

var NetworkSentBytesCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_sent_bytes_counter",
		Help: "Number of bytes sent",
	},
	[]string{"pod", "remote_subnet"},
)

var NetworkSentPacketsCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_sent_packets_counter",
		Help: "Number of packets sent",
	},
	[]string{"pod", "remote_subnet"},
)

var NetworkReceivedPacketsCounter = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "network_received_packets_counter",
		Help: "Number of packets received",
	},
	[]string{"pod", "remote_subnet"},
)
