package util

import (
	"strconv"
	"strings"
)

// 解析端口范围
func ExpandPorts(portRanges []string) []int {
	var ports []int

	for _, portRange := range portRanges {
		if strings.Contains(portRange, "-") {
			parts := strings.Split(portRange, "-")
			if len(parts) != 2 {
				// log.Fatalf("无效的端口范围: %s\n", portRange)
			}

			start, err1 := strconv.Atoi(parts[0])
			end, err2 := strconv.Atoi(parts[1])

			if err1 != nil || err2 != nil || start > end {
				// log.Fatalf("无效的端口范围: %s\n", portRange)
			}

			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			port, err := strconv.Atoi(portRange)
			if err != nil {
				// log.Fatalf("无效的端口: %s\n", portRange)
			}
			ports = append(ports, port)
		}
	}

	return ports
}