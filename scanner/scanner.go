package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/domain"
	"github.com/qist/iptv-static-scan/network"
	"github.com/qist/iptv-static-scan/util"
)

// 任务结构体，代表一个工作单元
type Task struct {
	IP       string       // IP 地址
	Executor func(string) // 执行函数，接收 IP 作为参数
}

// WorkerPool 结构体，表示一个执行任务的工作池
type WorkerPool struct {
	wg        sync.WaitGroup
	TaskQueue chan Task
	poolSize  int
}

// 创建一个指定大小的工作池
func NewWorkerPool(poolSize, bufferSize int) *WorkerPool {
	return &WorkerPool{
		TaskQueue: make(chan Task, bufferSize),
		poolSize:  poolSize,
	}
}

// 添加任务到工作池
func (wp *WorkerPool) AddTask(task Task) {
	wp.TaskQueue <- task
}

// 启动工作池并执行任务
func (wp *WorkerPool) Start() {
	wp.wg.Add(wp.poolSize)
	for i := 0; i < wp.poolSize; i++ {
		go wp.worker()
	}
}

// worker 函数，从任务队列中执行任务
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for task := range wp.TaskQueue {
		task.Executor(task.IP)
	}
}

// 等待所有任务完成
func (wp *WorkerPool) Wait() {
	wp.wg.Wait()
}

// 检查IP和端口是否可访问
func CheckIPPort(ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
	client := network.CreateHTTPClient(cfg)    // 复用创建HTTP客户端的代码
	req, err := network.CreateHTTPRequest(url) // 复用创建HTTP请求的代码
	if err != nil {
		log.Printf("创建请求失败: %v\n", err)
		return
	}
	req.Header = cfg.UAHeaders

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "redirected to HTTPS") {
			// 已经在CheckRedirect中处理日志记录
			log.Printf("ip: %s 已按指示断开HTTPS重定向的连接: %v\n", ip, err)
		} else {
			log.Printf("请求失败: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		// 调用 confirmAccess 函数，传递 IP、端口和 URL 路径
		ConfirmAccess(ip, port, urlPath, cfg, successfulIPsCh)
	} else {
		log.Printf("访问:%s, 状态码: %d\n", url, resp.StatusCode)
		return // 状态码不为200时直接返回
	}
}

// 确认访问成功后的操作
func ConfirmAccess(ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
	client := network.CreateHTTPClient(cfg)    // 复用创建HTTP客户端的代码
	req, err := network.CreateHTTPRequest(url) // 复用创建HTTP请求的代码
	if err != nil {
		log.Printf("创建请求失败: %v\n", err)
		return
	}
	req.Header = cfg.UAHeaders

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("发送请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		contentHeader := resp.Header.Get("Content-Type")
		serverHeader := resp.Header.Get("Server")

		if serverHeader != "" && strings.Contains(serverHeader, "udpxy") {
			log.Printf("访问 %s:%d 成功, Server: udpxy\n", ip, port)
			network.DownloadStream(ip, port, urlPath, cfg, successfulIPsCh)
		}

		if contentHeader != "" {
			if strings.Contains(contentHeader, "x-flv") || strings.Contains(contentHeader, "video") {
				network.DownloadStream(ip, port, urlPath, cfg, successfulIPsCh)
			} else if strings.Contains(contentHeader, "mpegurl") {
				network.CheckMPEGURLContent(ip, port, urlPath, cfg, successfulIPsCh)
			} else if strings.Contains(contentHeader, "text") {
				network.MkHTMLContent(ip, port, urlPath, cfg, successfulIPsCh)
			} else if strings.Contains(contentHeader, "application/json") {
				network.MkHTMLContent(ip, port, urlPath, cfg, successfulIPsCh)
			}
		}
	} else {
		log.Printf("请求 %s 失败, 状态码: %d\n", url, resp.StatusCode)
		return // 状态码不为200时直接返回
	}
}

// 解析CIDR文件并添加任务到 worker pool 处理
func AddTaskToPool(wp *WorkerPool, ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	// 添加任务到工作池
	wp.AddTask(Task{
		IP:       ip,
		Executor: func(ip string) { CheckIPPort(ip, port, urlPath, cfg, successfulIPsCh) },
	})
}

// 处理单个CIDR
func ProcessCIDR(workerPool *WorkerPool, cidr string, cfg *config.Config, successfulIPsCh chan<- string) error {
	// 创建一个带有缓冲区的通道来限制并发的 goroutine 数量
	sem := make(chan struct{}, cfg.MaxConcurrentRequest)

	// 判断是否为域名
	switch domain.IsDomain(cidr) {
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
					AddTaskToPool(workerPool, cidr, port, urlPath, cfg, successfulIPsCh)
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
					AddTaskToPool(workerPool, cidr, nonPort, nonPath, cfg, successfulIPsCh)
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
								AddTaskToPool(workerPool, ip, port, urlPath, cfg, successfulIPsCh)
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
								AddTaskToPool(workerPool, ip, nonPort, nonPath, cfg, successfulIPsCh)
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

// 判断是否为IPv6地址
func IsIPv6(ip net.IP) bool {
	return ip.To4() == nil
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

// 循环生成指定数量的 CIDR 对应的 IP 列表，直到整个 CIDR 结束，并返回指定数量的 IP 地址
func GenerateLimitedIPsFromCIDR(startIP net.IP, ipNet *net.IPNet, limit int) ([]string, bool) {
	var ips []string
	count := 0
	for ip := startIP; ipNet.Contains(ip); incrementIP(ip) {
		if isBadHost(ip.To4()) {
			continue // 跳过主机部分为 "0" 或 "255" 的 IP
		}
		ips = append(ips, ip.String())
		count++
		if count >= limit {
			break
		}
	}

	// 如果整个 CIDR 已经处理完毕，则返回 true
	if !ipNet.Contains(IncrementAndCopyIP(startIP, count)) {
		return ips, true
	}

	return ips, false
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
