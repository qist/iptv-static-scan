package cidr

import (
	"fmt"
	"net"
)

// 生成 CIDR 范围
func IPRangeToCIDRs(startIP, endIP string) ([]string, error) {
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if start == nil || end == nil {
		return nil, fmt.Errorf("无效的 IP 地址")
	}

	if IsIPv6(start) && IsIPv6(end) {
		// IPv6 地址处理
		if !ipLessThanOrEqual(start, end) {
			return nil, fmt.Errorf("startIP 必须小于或等于 endIP")
		}
		ips, err := ipv6RangeLimited(startIP, endIP)
		if err != nil {
			return nil, fmt.Errorf("错误: %v", err)
		}
		var cidrs []string
		for _, ip := range ips {
			cidrs = append(cidrs, fmt.Sprintf("%s/128", ip))
		}
		return cidrs, nil
	} else if isIPv4(start) && isIPv4(end) {
		// IPv4 地址处理
		if !ipLessThanOrEqual(start, end) {
			return nil, fmt.Errorf("startIP 必须小于或等于 endIP")
		}
		var cidrs []string
		for ip := start; ipLessThanOrEqual(ip, end); ip = nextIP(ip) {
			cidrs = append(cidrs, fmt.Sprintf("%s/32", ip.String()))
		}
		return cidrs, nil
	} else {
		return nil, fmt.Errorf("IP 地址必须是相同类型（IPv4 或 IPv6）")
	}
}

// 检查 IP 地址是否为 IPv4
func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// IsIPv6 检查 IP 地址是否为 IPv6
func IsIPv6(ip net.IP) bool {
	return ip.To4() == nil
}

// 获取下一个 IP 地址
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}
	return next
}

// 比较两个 IP 地址
func ipLessThanOrEqual(ip1, ip2 net.IP) bool {
	return bytesCompare(ip1, ip2) <= 0
}

// 自定义 bytes 比较，用于 IP 地址比较
func bytesCompare(ip1, ip2 net.IP) int {
	for i := 0; i < len(ip1); i++ {
		if ip1[i] < ip2[i] {
			return -1
		} else if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}