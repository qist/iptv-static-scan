package cidr

import (
	"fmt"
	"math/big"
	"net"
	"strings"
)

// 生成特定范围的IPv6地址，处理每一段的值
func ipv6RangeLimited(startIP, endIP string) ([]string, error) {
	// 解析起始和结束IPv6地址
	start := net.ParseIP(startIP).To16()
	end := net.ParseIP(endIP).To16()

	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IPv6 address")
	}

	// 确保前缀部分相同
	prefixLength := getCommonPrefixLength(startIP, endIP)
	startPrefix := strings.Join(strings.Split(startIP, ":")[:prefixLength], ":")
	endPrefix := strings.Join(strings.Split(endIP, ":")[:prefixLength], ":")
	if startPrefix != endPrefix {
		return nil, fmt.Errorf("start and end IP addresses must have the same prefix up to the common prefix length")
	}

	// 获取 IPv6 地址的各段部分
	startParts := strings.Split(startIP, ":")[prefixLength:]
	endParts := strings.Split(endIP, ":")[prefixLength:]

	// 生成地址范围
	var ips []string
	for _, address := range generateIPv6Addresses(startParts, endParts) {
		ip := fmt.Sprintf("%s:%s", startPrefix, address)
		// 判断是否需要添加 ::
		if len(strings.Split(ip, ":")) < 8 {
			ip = addCompression(ip)
		}
		ips = append(ips, ip)
	}

	// 去除重复的地址
	uniqueIPs := removeDuplicates(ips)
	return uniqueIPs, nil
}

// 生成从 startParts 到 endParts 的所有 IPv6 地址
func generateIPv6Addresses(startParts, endParts []string) []string {
	var result []string

	// 将每部分转换为大整数
	startInts := convertPartsToInts(startParts)
	endInts := convertPartsToInts(endParts)

	for i := 0; i < len(startParts); i++ {
		for j := new(big.Int).Set(startInts[i]); j.Cmp(endInts[i]) <= 0; j.Add(j, big.NewInt(1)) {
			address := fmt.Sprintf("%04x", j.Uint64())
			result = append(result, address)
		}
	}

	return result
}

// 将IPv6地址的每部分转换为大整数
func convertPartsToInts(parts []string) []*big.Int {
	ints := make([]*big.Int, len(parts))
	for i, part := range parts {
		ints[i] = new(big.Int)
		ints[i].SetBytes(parseHex(part))
	}
	return ints
}

// 解析16进制字符串
func parseHex(s string) []byte {
	bytes, success := new(big.Int).SetString(s, 16)
	if !success {
		return []byte{0}
	}
	return bytes.Bytes()
}

// 获取起始和结束地址的共同前缀长度
func getCommonPrefixLength(startIP, endIP string) int {
	startParts := strings.Split(startIP, ":")
	endParts := strings.Split(endIP, ":")
	prefixLength := 0
	for i := 0; i < len(startParts) && i < len(endParts); i++ {
		if startParts[i] == endParts[i] {
			prefixLength++
		} else {
			break
		}
	}
	return prefixLength
}

// 添加压缩 "::" 到 IPv6 地址的末尾部分
func addCompression(ip string) string {
	parts := strings.Split(ip, ":")
	for len(parts) < 8 {
		parts = append(parts, "0000")
	}
	return strings.Join(parts, ":")
}

// 移除重复的 IPv6 地址
func removeDuplicates(ips []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	return unique
}