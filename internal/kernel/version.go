package kernel

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// GetKernelVersion fetches the Linux kernel version without using exec commands.
// It reads the version directly from /proc/sys/kernel/osrelease.
func GetKernelVersion() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", fmt.Errorf("failed to read kernel version: %w", err)
	}
	version := strings.TrimSpace(string(data))
	return version, nil
}

// CompareVersions compares two kernel version strings.
// It returns 1 if v1 > v2, -1 if v1 < v2, and 0 if they are equal.
func CompareVersions(v1, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		var v1Num, v2Num int

		if i < len(v1Parts) {
			v1Num = extractLeadingNumber(v1Parts[i])
		}
		if i < len(v2Parts) {
			v2Num = extractLeadingNumber(v2Parts[i])
		}

		if v1Num > v2Num {
			return 1
		} else if v1Num < v2Num {
			return -1
		}
	}
	return 0
}

// extractLeadingNumber extracts the leading numeric part of a version string segment.
func extractLeadingNumber(s string) int {
	numStr := strings.TrimLeftFunc(s, func(r rune) bool {
		return r < '0' || r > '9'
	})
	numStr = strings.TrimRightFunc(numStr, func(r rune) bool {
		return r < '0' || r > '9'
	})
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return 0
	}
	return num
}
