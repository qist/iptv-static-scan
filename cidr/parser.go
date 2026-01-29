package cidr

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/scanner"
	"github.com/qist/iptv-static-scan/domain"
)

// 解析CIDR文件并添加任务到 worker pool 处理
func ParseCIDRFile(workerPool *scanner.WorkerPool, cfg *config.Config, successfulIPsCh chan<- string) error {
	file, err := os.Open(cfg.CIDRFile)
	if err != nil {
		return fmt.Errorf("打开CIDR文件失败: %v", err)
	}
	defer file.Close()

	scannerScanner := bufio.NewScanner(file)
	for scannerScanner.Scan() {
		line := scannerScanner.Text()
		line = strings.TrimSpace(line)

		// 检查是否为 ip:port 格式
		if strings.Contains(line, ":") && !strings.Contains(line, "/") && !strings.Contains(line, "-") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				ip := strings.TrimSpace(parts[0])
				portStr := strings.TrimSpace(parts[1])
				
				// 验证IP格式
				parsedIP := net.ParseIP(ip)
				if parsedIP != nil {
					// 验证端口格式
					port, err := strconv.Atoi(portStr)
					if err == nil && port > 0 && port <= 65535 {
						// 是 ip:port 格式，直接添加任务到 worker pool
						scanner.AddTaskToPool(workerPool, ip, port, "", cfg, successfulIPsCh)
						continue
					}
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