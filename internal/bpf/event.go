package bpf

import bpfarch "github.com/nullswan/bpfsnitch/internal/bpf/arch"

type SyscallEvent struct {
	SyscallNr int64
	Ts        uint64
	CgroupId  uint64
	Pid       uint64
}

func (s *SyscallEvent) GetSyscallName() string {
	return bpfarch.IdToSyscall[int(s.SyscallNr)]
}
