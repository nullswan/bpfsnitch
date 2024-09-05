package bpf

import bpfarch "github.com/nullswan/bpfsentinel/internal/bpf/arch"

type SyscallEvent struct {
	SyscallNr int64
	Ts        uint64
	UserId    uint64
	CgroupId  uint64
}

func (s *SyscallEvent) GetSyscallName() string {
	return bpfarch.WhitelistedSyscallsMap[int(s.SyscallNr)]
}
