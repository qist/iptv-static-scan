package cidr

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"strconv"
	"strings"
	"sync"

	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/domain"
	"github.com/qist/iptv-static-scan/scanner"
)

// 解析CIDR文件并添加任务到 worker pool 处理
func ParseCIDRFile(workerPool *scanner.WorkerPool, cfg *config.Config, successfulIPsCh chan<- string) error {
	file, err := os.Open(cfg.CIDRFile)
	if err != nil {
		return fmt.Errorf("打开CIDR文件失败: %v", err)
	}
	defer file.Close()

	scannerScanner := bufio.NewScanner(file)
	sem := make(chan struct{}, cfg.MaxConcurrentRequest)
	var wg sync.WaitGroup
	for scannerScanner.Scan() {
		line := scannerScanner.Text()
		line = strings.TrimSpace(line)

		// 检查是否为 ip:port 格式
		if isIPPortFormat(line) {
			ip, portStr, ok := parseIPPort(line)
			if ok {
				// 验证端口格式
				port, err := strconv.Atoi(portStr)
				if err == nil && port > 0 && port <= 65535 {
					// 是 ip:port 格式，直接添加任务到 worker pool
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
							scanner.AddTaskToPool(workerPool, ip, port, urlPath, cfg, successfulIPsCh)
						}(port, urlPath)
					}
					continue
				}
			}
		}

		// 检查是否为域名
		switch domain.IsDomain(line) {
		case 1:
			// 是域名且能解析，直接处理
			err := scanner.ProcessCIDR(workerPool, line, cfg, successfulIPsCh)
			if err != nil {
				log.Printf("处理域名失败: %v\n", err)
			}
			continue
		case 0:
			// 是域名但不能解析，跳过
			log.Printf("无法解析域名: %s\n", line)
			continue

		case 2:
			if strings.Contains(line, "-") {
				// 检查是否为IP范围格式
				ips := strings.Split(line, "-")
				if len(ips) == 2 {
					startIP := strings.TrimSpace(ips[0])
					endIP := strings.TrimSpace(ips[1])

					// 转换IP范围为CIDR
					cidrs, err := IPRangeToCIDRs(startIP, endIP)
					if err != nil {
						log.Printf("转换IP范围失败: %v\n", err)
						continue
					}
					// 处理每个CIDR
					for _, cidr := range cidrs {
						err := scanner.ProcessCIDR(workerPool, cidr, cfg, successfulIPsCh)
						if err != nil {
							log.Printf("处理CIDR失败: %v\n", err)
						}
					}
				} else {
					log.Printf("无效的IP范围格式: %s\n", line)
				}
			} else {
				// 如果是CIDR格式，直接处理
				err := scanner.ProcessCIDR(workerPool, line, cfg, successfulIPsCh)
				if err != nil {
					log.Printf("处理CIDR失败: %v\n", err)
				}
			}
		}
	}

	if err := scannerScanner.Err(); err != nil {
		return fmt.Errorf("读取CIDR文件失败: %v", err)
	}

	return nil
}

// isIPPortFormat 检查是否为 ip:port 格式，支持 IPv4 和 IPv6
func isIPPortFormat(line string) bool {
	if !strings.Contains(line, ":") {
		return false
	}

	// 对于 IPv6，格式可能是 [::1]:8080 这样的形式
	if strings.HasPrefix(line, "[") {
		// 需要有配对的方括号和端口
		closeBracketIndex := strings.LastIndex(line, "]")
		if closeBracketIndex == -1 || closeBracketIndex+2 > len(line) || line[closeBracketIndex+1] != ':' {
			return false
		}
		return true
	}

	// 对于 IPv4，计算冒号的数量
	// 如果是 CIDR 格式（如 192.168.1.0/24）或 IP 范围（如 10.0.0.1-10.0.0.254），则不是 ip:port 格式
	if strings.Contains(line, "/") || strings.Contains(line, "-") {
		return false
	}

	// IPv4:port 格式应该只有一个冒号，后面跟端口号
	parts := strings.Split(line, ":")
	if len(parts) == 2 {
		ip := strings.TrimSpace(parts[0])
		port := strings.TrimSpace(parts[1])

		// 验证 IP 部分是否是有效的 IP 地址
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			// 验证端口部分是否是有效的端口号
			portNum, err := strconv.Atoi(port)
			if err == nil && portNum > 0 && portNum <= 65535 {
				return true
			}
		}
	}

	return false
}

// parseIPPort 解析 ip:port 格式的字符串，返回 IP 和端口
func parseIPPort(line string) (ip, port string, ok bool) {
	if strings.HasPrefix(line, "[") {
		// IPv6 格式 [::1]:port
		closeBracketIndex := strings.LastIndex(line, "]")
		if closeBracketIndex == -1 {
			return "", "", false
		}
		ip = line[1:closeBracketIndex] // 去掉方括号
		if closeBracketIndex+2 <= len(line) && line[closeBracketIndex+1] == ':' {
			port = line[closeBracketIndex+2:]
		} else {
			return "", "", false
		}
	} else {
		// IPv4 格式 ip:port
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			return "", "", false
		}
		ip = strings.TrimSpace(parts[0])
		port = strings.TrimSpace(parts[1])
	}

	// 验证 IP 是否有效
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", "", false
	}

	return ip, port, true
}
