package network

import (
	"net"
	"reflect"
	"testing"
)

func TestIntToIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    uint32
		expected net.IP
	}{
		{
			name:     "Localhost",
			input:    0x7f000001,
			expected: net.IPv4(127, 0, 0, 1),
		},
		{
			name:     "Broadcast",
			input:    0xffffffff,
			expected: net.IPv4(255, 255, 255, 255),
		},
		{
			name:     "Zero",
			input:    0x00000000,
			expected: net.IPv4(0, 0, 0, 0),
		},
		{
			name:     "PrivateNetwork192",
			input:    0xc0a80001,
			expected: net.IPv4(192, 168, 0, 1),
		},
		{
			name:     "PrivateNetwork10",
			input:    0x0a000001,
			expected: net.IPv4(10, 0, 0, 1),
		},
		{
			name:     "PrivateNetwork172",
			input:    0xac100001,
			expected: net.IPv4(172, 16, 0, 1),
		},
		{
			name:     "Multicast",
			input:    0xe00000fb,
			expected: net.IPv4(224, 0, 0, 251),
		},
		{
			name:     "GoogleDNS",
			input:    0x08080808,
			expected: net.IPv4(8, 8, 8, 8),
		},
		{
			name:     "CloudflareDNS",
			input:    0x01010101,
			expected: net.IPv4(1, 1, 1, 1),
		},
		{
			name:     "RandomIP1",
			input:    0x12345678,
			expected: net.IPv4(18, 52, 86, 120),
		},
		{
			name:     "RandomIP2",
			input:    0x87654321,
			expected: net.IPv4(135, 101, 67, 33),
		},
		{
			name:     "RandomIP3",
			input:    0xaabbccdd,
			expected: net.IPv4(170, 187, 204, 221),
		},
		{
			name:     "MaxValue",
			input:    0xffffffff,
			expected: net.IPv4(255, 255, 255, 255),
		},
		{
			name:     "MinValue",
			input:    0x00000000,
			expected: net.IPv4(0, 0, 0, 0),
		},
	}

	for _, test := range tests {
		test := test // capture range variable
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := IntToIP(test.input)
			if !result.Equal(test.expected) {
				t.Errorf(
					"IntToIP(%#x) = %s; want %s",
					test.input,
					result,
					test.expected,
				)
			}
		})
	}
}

func TestNtohs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    uint16
		expected uint16
	}{
		{
			name:     "Zero",
			input:    0x0000,
			expected: 0x0000,
		},
		{
			name:     "MaxValue",
			input:    0xffff,
			expected: 0xffff,
		},
		{
			name:     "Port80",
			input:    0x5000,
			expected: 0x0050,
		},
		{
			name:     "Port443",
			input:    0xbb01,
			expected: 0x01bb,
		},
		{
			name:     "Port22",
			input:    0x1600,
			expected: 0x0016,
		},
		{
			name:     "RandomValue1",
			input:    0x3412,
			expected: 0x1234,
		},
		{
			name:     "RandomValue2",
			input:    0x7856,
			expected: 0x5678,
		},
		{
			name:     "RandomValue3",
			input:    0xa1b2,
			expected: 0xb2a1,
		},
		{
			name:     "HighByteZero",
			input:    0x00ff,
			expected: 0xff00,
		},
		{
			name:     "LowByteZero",
			input:    0xff00,
			expected: 0x00ff,
		},
		{
			name:     "AlternatingBits",
			input:    0xaa55,
			expected: 0x55aa,
		},
		{
			name:     "Palindrome",
			input:    0x1a1a,
			expected: 0x1a1a,
		},
	}

	for _, test := range tests {
		test := test // capture range variable
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := Ntohs(test.input)
			if result != test.expected {
				t.Errorf(
					"Ntohs(%#x) = %#x; want %#x",
					test.input,
					result,
					test.expected,
				)
			}
		})
	}
}

func TestNtohl(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    uint32
		expected uint32
	}{
		{
			name:     "Zero",
			input:    0x00000000,
			expected: 0x00000000,
		},
		{
			name:     "MaxValue",
			input:    0xffffffff,
			expected: 0xffffffff,
		},
		{
			name:     "Localhost",
			input:    0x0100007f,
			expected: 0x7f000001,
		},
		{
			name:     "GoogleDNS",
			input:    0x08080808,
			expected: 0x08080808,
		},
		{
			name:     "PrivateNetwork192",
			input:    0xC0A80001,
			expected: 0x0100A8C0,
		},
		{
			name:     "RandomValue1",
			input:    0x78563412,
			expected: 0x12345678,
		},
		{
			name:     "RandomValue2",
			input:    0x44332211,
			expected: 0x11223344,
		},
		{
			name:     "HighBytesZero",
			input:    0x0000ffff,
			expected: 0xffff0000,
		},
		{
			name:     "LowBytesZero",
			input:    0xffff0000,
			expected: 0x0000ffff,
		},
		{
			name:     "AlternatingBits",
			input:    0xaa55aa55,
			expected: 0x55aa55aa,
		},
		{
			name:     "Palindrome",
			input:    0x1a2b2b1a,
			expected: 0x1a2b2b1a,
		},
		{
			name:     "Multicast",
			input:    0xfb0000e0,
			expected: 0xe00000fb,
		},
		{
			name:     "EdgeCase1",
			input:    0x00000001,
			expected: 0x01000000,
		},
		{
			name:     "EdgeCase2",
			input:    0x80000000,
			expected: 0x00000080,
		},
	}

	for _, test := range tests {
		test := test // capture range variable
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := Ntohl(test.input)
			if result != test.expected {
				t.Errorf(
					"Ntohl(%#x) = %#x; want %#x",
					test.input,
					result,
					test.expected,
				)
			}
		})
	}
}

func TestIntToSubnet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ip     uint32
		mask   uint32
		output *net.IPNet
	}{
		{
			ip:   0xC0A80101, // 192.168.1.1
			mask: 0xFFFFFF00, // 255.255.255.0
			output: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 0),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
		},
		{
			ip:   0x0A000001, // 10.0.0.1
			mask: 0xFF000000, // 255.0.0.0
			output: &net.IPNet{
				IP:   net.IPv4(10, 0, 0, 0),
				Mask: net.IPv4Mask(255, 0, 0, 0),
			},
		},
		{
			ip:   0xC0A80101, // 192.168.1.1
			mask: 0xFFFF0000, // 255.255.0.0
			output: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 0), // Host portion is zeroed out
				Mask: net.IPv4Mask(255, 255, 0, 0),
			},
		},
		{
			ip:   0xC0A80101, // 192.168.1.1
			mask: 0xFFFFFFFF, // 255.255.255.255
			output: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 1), // No part is zeroed out
				Mask: net.IPv4Mask(255, 255, 255, 255),
			},
		},
		{
			ip:   0x0A0A0A0A, // 10.10.10.10
			mask: 0xFFFFF000, // 255.255.240.0
			output: &net.IPNet{
				IP:   net.IPv4(10, 10, 0, 0), // Host portion is zeroed out
				Mask: net.IPv4Mask(255, 255, 240, 0),
			},
		},
		{
			ip:   0xAC100202, // 172.16.2.2
			mask: 0xFFFFFFF0, // 255.255.255.240
			output: &net.IPNet{
				IP: net.IPv4(
					172,
					16,
					2,
					0,
				), // Host portion is mostly zeroed out
				Mask: net.IPv4Mask(255, 255, 255, 240),
			},
		},
	}

	for _, tt := range tests {
		result := IntToSubnet(tt.ip, tt.mask)
		if !reflect.DeepEqual(result, tt.output) {
			t.Errorf(
				"IntToSubnet(%v, %v) = %v; want %v",
				tt.ip,
				tt.mask,
				result,
				tt.output,
			)
		}
	}
}
