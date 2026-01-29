package cidr

import (
	"fmt"
	"net"

)

// 循环生成指定数量的 CIDR 对应的 IP 列表，直到整个 CIDR 结束，并返回指定数量的 IP 地址
func GenerateLimitedIPsFromCIDR(startIP net.IP, ipNet *net.IPNet, limit int) ([]string, bool) {
	var ips []string
	count := 0
	
	// 确保不超过限制
	ips = make([]string, 0, limit)
	
	for ip := startIP; ipNet.Contains(ip) && count < limit; incrementIP(ip) {
		if isBadHost(ip.To4()) {
			continue // 跳过主机部分为 "0" 或 "255" 的 IP
		}
		ips = append(ips, ip.String())
		count++
	}

	// 如果整个 CIDR 已经处理完毕，则返回 true
	nextIP := IncrementAndCopyIP(startIP, count)
	completed := !ipNet.Contains(nextIP)
	
	return ips, completed
}

// 增加并复制 IP 地址
func IncrementAndCopyIP(ip net.IP, n int) net.IP {
	nextIP := make(net.IP, len(ip))
	copy(nextIP, ip)
	for i := len(nextIP) - 1; i >= 0; i-- {
		nextIP[i] += byte(n)
		if nextIP[i] > 0 {
			break
		}
	}
	return nextIP
}

// 增加IP地址
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isBadHost 检查 IPv4 地址的最后一个八位组（即主机部分）是否为 "0" 或 "255"。
func isBadHost(ip net.IP) bool {
	if len(ip) != 4 {
		return false
	}
	lastOctet := ip[3]
	return lastOctet == 0 || lastOctet == 255
}



// 检查IP是否为单个IP
func IsSingleIP(ipStr string) bool {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}

	// Check for IPv4
	if parsedIP.To4() != nil {
		return true
	}

	// Check for IPv6
	if parsedIP.To16() != nil {
		return true
	}

	return false
}

// 从单个IP获取CIDR
func GetCIDRFromSingleIP(ipStr string) string {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return "" // 返回空字符串表示无效 IP
	}

	// 检查是否为 IPv4
	if parsedIP.To4() != nil {
		return fmt.Sprintf("%s/32", parsedIP.String())
	}

	// 检查是否为 IPv6
	if parsedIP.To16() != nil {
		return fmt.Sprintf("%s/128", parsedIP.String())
	}

	return "" // 不支持的 IP 类型
}

// 解析CIDR字符串并返回IPNet对象
func ParseCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipNet, nil
}
