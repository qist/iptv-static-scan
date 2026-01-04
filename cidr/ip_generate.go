package cidr

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/scanner"
	"github.com/qist/iptv-static-scan/util"
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

// 判断输入是否为域名
func isDomain(input string) int {
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

// 处理单个CIDR
func processCIDR(workerPool *scanner.WorkerPool, cidr string, cfg *config.Config) error {
	// 创建一个带有缓冲区的通道来限制并发的 goroutine 数量
	sem := make(chan struct{}, cfg.MaxConcurrentRequest)

	// 判断是否为域名
	switch isDomain(cidr) {
	case 1:
		// 如果是域名，直接生成 URL，受 MaxConcurrentRequest 限制
		var wg sync.WaitGroup
		for _, port := range util.ExpandPorts(cfg.Ports) {
			for _, urlPath := range cfg.URLPaths {
				wg.Add(1)
				sem <- struct{}{}
				go func(port int, urlPath string) {
					defer wg.Done()
					defer func() { <-sem }()

					// 获取当前时间戳，并截取前9位
					timestamp := int(time.Now().Unix())
					timestampStr := fmt.Sprintf("%d", timestamp)[:9]
					timestampInt, err := strconv.Atoi(timestampStr)
					if err != nil {
						log.Fatalf("转换时间戳失败: %v", err)
					}

					// 将截取的时间戳减去5秒
					timestampMinus5 := timestampInt - 5

					// 获取当前日期时间，并按照指定格式格式化
					timeFirst := time.Now().Format("2006010215")
					// 动态替换 URL 中的变量
					if strings.Contains(urlPath, "{timeFirst}") || strings.Contains(urlPath, "{timestampMinus5}") {
						urlPath = strings.Replace(urlPath, "{timeFirst}", timeFirst, -1)
						urlPath = strings.Replace(urlPath, "{timestampMinus5}", strconv.Itoa(timestampMinus5), -1)
					}
					scanner.AddTaskToPool(workerPool, cidr, port, urlPath, cfg)
				}(port, urlPath)
			}
		}
		// 处理非循环端口
		for _, nonPortPath := range cfg.NonPortsPath {
			parts := strings.SplitN(nonPortPath, "/", 2)
			if len(parts) == 2 {
				nonPortStr := parts[0]
				nonPath := parts[1]

				wg.Add(1)
				sem <- struct{}{}
				go func(nonPortStr, nonPath string) {
					defer wg.Done()
					defer func() { <-sem }()

					// 处理非循环端口
					nonPort, err := strconv.Atoi(nonPortStr)
					if err != nil {
						log.Printf("无效的非循环端口: %s, 错误: %v", nonPortStr, err)
						return
					}

					// 获取当前时间戳，并截取前9位
					timestamp := int(time.Now().Unix())
					timestampStr := fmt.Sprintf("%d", timestamp)[:9]
					timestampInt, err := strconv.Atoi(timestampStr)
					if err != nil {
						log.Fatalf("转换时间戳失败: %v", err)
					}

					// 将截取的时间戳减去5秒
					timestampMinus5 := timestampInt - 5

					// 获取当前日期时间，并按照指定格式格式化
					timeFirst := time.Now().Format("2006010215")
					// 动态替换 URL 中的变量
					if strings.Contains(nonPath, "{timeFirst}") || strings.Contains(nonPath, "{timestampMinus5}") {
						nonPath = strings.Replace(nonPath, "{timeFirst}", timeFirst, -1)
						nonPath = strings.Replace(nonPath, "{timestampMinus5}", strconv.Itoa(timestampMinus5), -1)
					}
					// 添加任务到 worker pool
					scanner.AddTaskToPool(workerPool, cidr, nonPort, nonPath, cfg)
				}(nonPortStr, nonPath)
			} else {
				log.Printf("无效的非循环端口路径格式: %s", nonPortPath)
			}
		}
		wg.Wait()
	case 2:
		// 2. 判断是否是单个 IP
		if IsSingleIP(cidr) {
			// 如果是单个 IP，直接加入列表中
			cidr = GetCIDRFromSingleIP(cidr)
		}

		ipNet, err := ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("解析CIDR失败：%v", err)
		}

		completed := false
		startIP := ipNet.IP.Mask(ipNet.Mask) // 初始 IP
		limit := cfg.MaxConcurrentRequest    // 每次生成的 IP 数量
		// log.Printf("初始ip: %s\n", startIP)
		for !completed {
			// 生成指定数量的 IP 地址
			ips, isCompleted := GenerateLimitedIPsFromCIDR(startIP, ipNet, limit)
			if len(ips) == 0 {
				return nil // 如果 IP 地址列表为空，则直接返回
			}

			// 将批次的 IP 地址并行分配给 worker pool 处理
			var wg sync.WaitGroup
			for _, ip := range ips {
				// log.Printf("eee: %s\n", ips)
				if IsIPv6(ipNet.IP) {
					ip = fmt.Sprintf("[%s]", ip)
				}
				wg.Add(1)

				sem <- struct{}{}
				go func(ip string) {
					defer wg.Done()
					defer func() { <-sem }()

					// 设置超时上下文
					ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeOut)*time.Second)
					defer cancel()

					for _, port := range util.ExpandPorts(cfg.Ports) {
						for _, urlPath := range cfg.URLPaths {
							select {
							case <-ctx.Done():
								log.Printf("处理 IP %s 超时", ip)
								return
							default:
								// 获取当前时间戳，并截取前9位
								timestamp := int(time.Now().Unix())
								timestampStr := fmt.Sprintf("%d", timestamp)[:9]
								timestampInt, err := strconv.Atoi(timestampStr)
								if err != nil {
									log.Fatalf("转换时间戳失败: %v", err)
								}

								// 将截取的时间戳减去5秒
								timestampMinus5 := timestampInt - 5

								// 获取当前日期时间，并按照指定格式格式化
								timeFirst := time.Now().Format("2006010215")
								// 动态替换 URL 中的变量
								if strings.Contains(urlPath, "{timeFirst}") || strings.Contains(urlPath, "{timestampMinus5}") {
									urlPath = strings.Replace(urlPath, "{timeFirst}", timeFirst, -1)
									urlPath = strings.Replace(urlPath, "{timestampMinus5}", strconv.Itoa(timestampMinus5), -1)
								}
								scanner.AddTaskToPool(workerPool, ip, port, urlPath, cfg)
							}
						}
					}
					// 处理非循环端口
					for _, nonPortPath := range cfg.NonPortsPath {
						parts := strings.SplitN(nonPortPath, "/", 2)
						if len(parts) == 2 {
							nonPortStr := parts[0]
							nonPath := parts[1]

							// 处理非循环端口
							nonPort, err := strconv.Atoi(nonPortStr)
							if err != nil {
								log.Printf("无效的非循环端口: %s, 错误: %v", nonPortStr, err)
								continue
							}
							select {
							case <-ctx.Done():
								log.Printf("处理 IP %s 超时", ip)
								return
							default:
								// 获取当前时间戳，并截取前9位
								timestamp := int(time.Now().Unix())
								timestampStr := fmt.Sprintf("%d", timestamp)[:9]
								timestampInt, err := strconv.Atoi(timestampStr)
								if err != nil {
									log.Fatalf("转换时间戳失败: %v", err)
								}

								// 将截取的时间戳减去5秒
								timestampMinus5 := timestampInt - 5

								// 获取当前日期时间，并按照指定格式格式化
								timeFirst := time.Now().Format("2006010215")
								// 动态替换 URL 中的变量
								if strings.Contains(nonPath, "{timeFirst}") || strings.Contains(nonPath, "{timestampMinus5}") {
									nonPath = strings.Replace(nonPath, "{timeFirst}", timeFirst, -1)
									nonPath = strings.Replace(nonPath, "{timestampMinus5}", strconv.Itoa(timestampMinus5), -1)
								}
								// 添加任务到 worker pool
								scanner.AddTaskToPool(workerPool, ip, nonPort, nonPath, cfg)
							}
						} else {
							log.Printf("无效的非循环端口路径格式: %s", nonPortPath)
						}
					}
				}(ip)
			}
			wg.Wait()

			// 递增 IP 地址，准备生成下一批 IP 地址
			startIP = IncrementAndCopyIP(startIP, limit)
			completed = isCompleted
		}
	}

	return nil
}
