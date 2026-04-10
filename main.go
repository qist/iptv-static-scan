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
	"github.com/qist/iptv-static-scan/webui"
)

var VersionFlag *bool

func main() {
	configFile := flag.String("config", "config.yaml", "配置文件的路径")
	webMode := flag.Bool("web", false, "启动 Web UI（不读取 YAML）")
	webAddr := flag.String("addr", "127.0.0.1:8080", "Web 服务监听地址（仅 -web）")
	VersionFlag = flag.Bool("version", false, "显示版本号")
	flag.Parse()

	if *VersionFlag {
		fmt.Println("程序版本:", config.Version)
		return
	}

	if *webMode {
		if err := webui.Start(*webAddr); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := runCLIScan(*configFile); err != nil {
		log.Fatal(err)
	}
}

func runCLIScan(configFile string) error {
	start := time.Now()
	fmt.Println("扫描开始: ", time.Now().Format("2006-01-02 15:04:05"))

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %w", err)
	}

	if !cfg.LogEnabled {
		log.SetOutput(io.Discard)
	}

	if err := output.ClearFileContent(cfg.SuccessfulIPsFile); err != nil {
		return fmt.Errorf("清空文件内容失败: %w", err)
	}

	successfulIPsCh := make(chan string, cfg.FileBufferSize)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for successfulIP := range successfulIPsCh {
			if err := output.AppendToFile(cfg.SuccessfulIPsFile, successfulIP); err != nil {
				log.Printf("写入成功的IP到文件失败: %v\n", err)
			}
		}
	}()

	bufferSize := cfg.MaxConcurrentRequest * 1024
	workerPool := scanner.NewWorkerPool(cfg.MaxConcurrentRequest, bufferSize)
	workerPool.Start()

	if err := cidr.ParseCIDRFile(workerPool, cfg, successfulIPsCh); err != nil {
		return fmt.Errorf("解析CIDR文件失败: %w", err)
	}

	close(workerPool.TaskQueue)
	workerPool.Wait()
	close(successfulIPsCh)
	wg.Wait()

	if err := output.DeleteStreamFiles(); err != nil {
		return fmt.Errorf("删除文件失败: %w", err)
	}

	elapsed := time.Since(start)
	fmt.Println("总扫描时间: ", elapsed)
	fmt.Println("扫描结束: ", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("扫描完成请看文件:", cfg.SuccessfulIPsFile)
	return nil
}
