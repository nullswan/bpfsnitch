package bpfarch

import "testing"

func TestWhitelistedSyscalls(t *testing.T) {
	for name, number := range WhitelistedSyscalls {
		if mappedName, present := WhitelistedSyscallsMap[number]; !present ||
			mappedName != name {
			t.Errorf(
				"Mismatch or missing entry: syscalls name %s with number %d not found in reverse map",
				name,
				number,
			)
		}
	}

	for number, name := range WhitelistedSyscallsMap {
		if mappedNumber, present := WhitelistedSyscalls[name]; !present ||
			mappedNumber != number {
			t.Errorf(
				"Mismatch or missing entry: syscalls number %d with name %s not found in forward map",
				number,
				name,
			)
		}
	}
}
