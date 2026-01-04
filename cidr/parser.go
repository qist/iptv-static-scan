package cidr

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/scanner"
)

// 解析CIDR文件并添加任务到 worker pool 处理
func ParseCIDRFile(workerPool *scanner.WorkerPool, cfg *config.Config) error {
	file, err := os.Open(cfg.CIDRFile)
	if err != nil {
		return fmt.Errorf("打开CIDR文件失败: %v", err)
	}
	defer file.Close()

	scannerScanner := bufio.NewScanner(file)
	for scannerScanner.Scan() {
		line := scannerScanner.Text()

		// 检查是否为域名
		switch isDomain(line) {
		case 1:
			// 是域名且能解析，直接处理
			err := scanner.ProcessCIDR(workerPool, line, cfg)
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
						err := scanner.ProcessCIDR(workerPool, cidr, cfg)
						if err != nil {
							log.Printf("处理CIDR失败: %v\n", err)
						}
					}
				} else {
					log.Printf("无效的IP范围格式: %s\n", line)
				}
			} else {
				// 如果是CIDR格式，直接处理
				err := scanner.ProcessCIDR(workerPool, line, cfg)
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
