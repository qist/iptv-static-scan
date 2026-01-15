package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/qist/iptv-static-scan/cidr"
	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/output"
	"github.com/qist/iptv-static-scan/scanner"
)
var VersionFlag *bool
func main() {
	// 使用flag包解析命令行参数
	configFile := flag.String("config", "config.yaml", "配置文件的路径")
	VersionFlag = flag.Bool("version", false, "显示版本号")
	flag.Parse()

	// 如果显示版本号，打印版本号并退出
	if *VersionFlag {
		fmt.Println("程序版本:", config.Version)
		return
	}
	
	start := time.Now() // 记录开始时间
	fmt.Println("扫描开始: ", time.Now().Format("2006-01-02 15:04:05"))

	// 加载配置文件
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		fmt.Println("加载配置文件失败:", err)
		return
	}

	// 设置日志记录器
	if !cfg.LogEnabled {
		log.SetOutput(io.Discard)
	}

	// 清空文件内容
	err = output.ClearFileContent(cfg.SuccessfulIPsFile)
	if err != nil {
		log.Printf("清空文件内容失败: %v\n", err)
		return
	}

	successfulIPsCh := make(chan string, cfg.FileBufferSize)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for successfulIP := range successfulIPsCh {
			err := output.AppendToFile(cfg.SuccessfulIPsFile, successfulIP)
			if err != nil {
				log.Printf("写入成功的IP到文件失败: %v\n", err)
			}
		}
	}()

	BufferSize := cfg.MaxConcurrentRequest * 1024
	// 创建并启动 worker pool
	workerPool := scanner.NewWorkerPool(cfg.MaxConcurrentRequest, BufferSize)
	workerPool.Start()

	// 解析 CIDR 文件并直接添加任务到 worker pool
	err = cidr.ParseCIDRFile(workerPool, cfg, successfulIPsCh)
	if err != nil {
		log.Printf("解析CIDR文件失败: %v\n", err)
		return
	}

	// Task 向管道写入完关闭管道
	close(workerPool.TaskQueue)
	// // 等待所有任务完成
	workerPool.Wait()
	// 关闭成功 IP 通道
	close(successfulIPsCh)
	wg.Wait()
	// 删除所有以 "stream9527_" 开头的文件
	err = output.DeleteStreamFiles()
	if err != nil {
		log.Fatalf("删除文件失败: %v", err)
	}

	elapsed := time.Since(start) // 计算并获取已用时间
	fmt.Println("总扫描时间: ", elapsed)
	fmt.Println("扫描结束: ", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("扫描完成请看文件:", cfg.SuccessfulIPsFile)
}
