package bpfarch

import "testing"

func TestSyscallDefs(t *testing.T) {
	for name, number := range SyscallToId {
		if mappedName, present := IdToSyscall[number]; !present ||
			mappedName != name {
			t.Errorf(
				"Mismatch or missing entry: syscall name %s with number %d not found in reverse map",
				name,
				number,
			)
		}
	}

	for number, name := range IdToSyscall {
		if mappedNumber, present := SyscallToId[name]; !present ||
			mappedNumber != number {
			t.Errorf(
				"Mismatch or missing entry: syscall number %d with name %s not found in forward map",
				number,
				name,
			)
		}
	}
}
