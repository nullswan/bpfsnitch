package bpf

import bpfarch "github.com/nullswan/bpfsnitch/internal/bpf/arch"

type Event interface {
	SyscallEvent | NetworkEvent
}

type SyscallEvent struct {
	SyscallNr int64
	CgroupID  uint64
	Pid       uint64
}

func (s SyscallEvent) GetSyscallName() string {
	return bpfarch.IdToSyscall[int(s.SyscallNr)]
}

type NetworkEvent struct {
	Pid      uint64
	CgroupID uint64
	Size     uint64

	Saddr uint32
	Daddr uint32

	Sport uint16
	Dport uint16

	Direction NetworkEventDirection
	Protocol  NetworkEventProtocol
}

type NetworkEventDirection uint8

const (
	NetworkEventDirectionInbound  NetworkEventDirection = 0
	NetworkEventDirectionOutbound NetworkEventDirection = 1
)

func (d NetworkEventDirection) String() string {
	if d == NetworkEventDirectionInbound {
		return "inbound"
	}
	return "outbound"
}

type NetworkEventProtocol uint8

const (
	NetworkEventProtocolTCP NetworkEventProtocol = 6
	NetworkEventProtocolUDP NetworkEventProtocol = 17
)

func (p NetworkEventProtocol) String() string {
	if p == NetworkEventProtocolTCP {
		return "tcp"
	}
	return "udp"
}
