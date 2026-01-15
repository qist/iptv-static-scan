package network

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/util"
)

// 下载流媒体文件
func DownloadStream(ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	var DownSize = int(float64(cfg.DownSize) * 1024 * 1024)
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)
	log.Printf("开始下载 http://%s:%d/%s\n", ip, port, urlPath)
	client := CreateHTTPClient(cfg)    // 复用创建HTTP客户端的代码
	req, err := CreateHTTPRequest(url) // 复用创建HTTP请求的代码
	if err != nil {
		log.Printf("创建请求失败: %v\n", err)
		return
	}
	req.Header = cfg.UAHeaders // 设置请求头

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("下载 http://%s:%d/%s 失败: %v\n", ip, port, urlPath, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("下载 http://%s:%d/%s 失败: 状态码 %d\n", ip, port, urlPath, resp.StatusCode)
		return
	}

	serverHeader := resp.Header.Get("Server")
	fileSize := 0

	ippath := strings.ReplaceAll(ip, ".", "_")
	ippath = strings.ReplaceAll(ippath, ":", "_")
	filename := util.GenerateFilename(urlPath)
	filename = strings.Trim(filename, "_")
	file, err := os.Create(fmt.Sprintf("stream9527_%s_%d_%s", ippath, port, filename))
	if err != nil {
		log.Printf("创建文件失败: %v\n", err)
		return
	}
	defer file.Close()

	for {
		chunk := make([]byte, DownSize)
		n, err := resp.Body.Read(chunk)
		if err != nil && err != io.EOF {
			log.Printf("读取响应体失败: %v\n", err)
			os.Remove(fmt.Sprintf("stream9527_%s_%d_%s", ippath, port, filename))
			log.Printf("读取响应体失败 删除文件 stream9527_%s_%d_%s\n", ippath, port, filename)
			return
		}
		if n == 0 {
			break
		}
		if _, err := file.Write(chunk[:n]); err != nil {
			log.Printf("写入文件失败: %v\n", err)
			os.Remove(fmt.Sprintf("stream9527_%s_%d_%s", ippath, port, filename))
			log.Printf("写入文件失败 删除文件 stream9527_%s_%d_%s\n", ippath, port, filename)
			return
		}
		fileSize += n
		if fileSize >= DownSize {
			break
		}
	}
	duration := time.Since(start)                                 // 下载耗时
	speed := float64(fileSize) / 1024 / 1024 / duration.Seconds() // MB/s
	if fileSize >= DownSize {
		log.Printf("下载完成 http://%s:%d/%s, 耗时: %v, 速度: %.2f MB/s\n", ip, port, urlPath, duration, speed)
		os.Remove(fmt.Sprintf("stream9527_%s_%d_%s", ippath, port, filename))
		log.Printf("删除文件 stream9527_%s_%d_%s\n", ippath, port, filename)
		outputString := ""
		outputString = util.GenerateOutputString(ip, port, urlPath, serverHeader, cfg, duration, &speed)
		// 去除输出字符串的首尾空白字符
		trimmedOutput := strings.TrimSpace(outputString)
		// 在写入文件之前检查去除空白后的字符串是否为空
		if trimmedOutput != "" {
			successfulIPsCh <- trimmedOutput
		}
	} else {
		os.Remove(fmt.Sprintf("stream9527_%s_%d_%s", ippath, port, filename))
		log.Printf("删除 文件大小未达到%.1fMB stream9527_%s_%d_%s\n", cfg.DownSize, ippath, port, filename)
		log.Printf("下载 http://%s:%d/%s 的流媒体文件成功, 但文件大小未达到%.1fMB\n", ip, port, urlPath, cfg.DownSize)
	}
}

func DownloadTS(ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)

	log.Printf("检查 %s 内容是否包含可下载ts文件\n", url)

	client := CreateHTTPClient(cfg)    // 复用创建HTTP客户端的代码
	req, err := CreateHTTPRequest(url) // 复用创建HTTP请求的代码
	if err != nil {
		log.Printf("创建请求失败: %v\n", err)
		return
	}
	req.Header = cfg.UAHeaders // 设置请求头

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求 %s 失败: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("读取 %s 响应体失败: %v\n", url, err)
			return
		}

		m3u8Content := string(body)
		// 获取第一个.ts文件的URL
		tsFile := GetFirstTSFile(m3u8Content)
		if tsFile != "" {
			baseURL := path.Dir(urlPath)
			tsURLPath := fmt.Sprintf("%s/%s", baseURL, tsFile)
			tsURLPath = strings.ReplaceAll(tsURLPath, "./", "")
			DownloadStream(ip, port, tsURLPath, cfg, successfulIPsCh)
		} else {
			log.Printf("未找到 .ts 文件")
		}
	} else {
		log.Printf("请求 %s 失败, 状态码: %d\n", url, resp.StatusCode)
		return // 状态码不为200时直接返回
	}
}

func GetFirstTSFile(m3u8Content string) string {
	lines := strings.Split(m3u8Content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ".ts") {
			return line
		}
	}
	return ""
}
