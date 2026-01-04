package domain

import (
	"net"
	"strings"
	"unicode"
)

// 判断输入是否为域名
func IsDomain(input string) int {
    // 检查是否为合法的 IP 地址（包括 IPv6 和 IPv4）
    if ip := net.ParseIP(input); ip != nil {
        if ip.To4() == nil {
            return 2 // 是 IPv6 地址，排除
        }
        return 2 // 是 IPv4 地址，排除
    }

    // 检查是否为合法的子网（包括 IPv6 和 IPv4）
    if _, _, err := net.ParseCIDR(input); err == nil {
        return 2 // 是子网，排除
    }

    // 检查是否为 IP 区间（仅排除特定格式的区间）
    if isIPRange(input) {
        return 2 // 是 IP 区间，排除
    }

    // 检查是否包含字母，判断是否可能为域名
    if containsLetter(input) {
        // 尝试解析域名
        if isResolvableDomain(input) {
            return 1 // 是域名且能解析
        }
        return 0 // 是域名但不能解析
    }

    return 2 // 不包含字母，不是域名
}

// 判断是否为 IP 区间（IPv4 或 IPv6）
func isIPRange(input string) bool {
    parts := strings.Split(input, "-")
    if len(parts) == 2 {
        startIP := net.ParseIP(parts[0])
        endIP := net.ParseIP(parts[1])
        // 确保这两个部分都是有效的 IP 地址（IPv4 或 IPv6）
        if startIP != nil && endIP != nil {
            return true
        }
    }
    return false
}

// 检查字符串是否包含字母
func containsLetter(s string) bool {
    for _, r := range s {
        if unicode.IsLetter(r) {
            return true
        }
    }
    return false
}

// 检查域名是否能解析
func isResolvableDomain(domain string) bool {
    _, err := net.LookupIP(domain)
    return err == nil
}