package network

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/util"
)

// maxBodySize 限制响应体读取大小，防止 OOM
const maxBodySize = 2 * 1024 * 1024 // 2MB

// CheckMPEGURLContent 检查MPEGURL内容（独立请求版本，供 DownloadTS 调用）
func CheckMPEGURLContent(ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)

	log.Printf("检查 %s 内容是否包含 'EXT-X-VERSION' 或者 'EXT-X-STREAM-INF'\n", url)

	client := GetHTTPClient(cfg)
	req, err := CreateHTTPRequest(url)
	if err != nil {
		log.Printf("创建请求失败: %v\n", err)
		return
	}
	req.Header = cfg.UAHeaders

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		log.Printf("请求 %s 失败: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		serverHeader := resp.Header.Get("Server")
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			log.Printf("读取 %s 响应体失败: %v\n", url, err)
			return
		}
		processMPEGURLBody(ip, port, urlPath, serverHeader, body, cfg, successfulIPsCh, duration)
	} else {
		log.Printf("请求 %s 失败, 状态码: %d, 耗时: %v\n", url, resp.StatusCode, duration)
	}
}

// CheckMPEGURLBody 检查MPEGURL内容（复用已有 body，避免重复请求）
func CheckMPEGURLBody(ip string, port int, urlPath string, serverHeader string, body []byte, cfg *config.Config, successfulIPsCh chan<- string, duration time.Duration) {
	processMPEGURLBody(ip, port, urlPath, serverHeader, body, cfg, successfulIPsCh, duration)
}

func processMPEGURLBody(ip string, port int, urlPath string, serverHeader string, body []byte, cfg *config.Config, successfulIPsCh chan<- string, duration time.Duration) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)

	m3u8Content := string(body)
	containsVersion := strings.Contains(m3u8Content, "EXT-X-VERSION")
	containsStream := strings.Contains(m3u8Content, "EXT-X-STREAM-INF")
	containsDefaultVhost := strings.Contains(m3u8Content, "_defaultVhost_")
	containsSegments := strings.Contains(m3u8Content, "EXT-X-INDEPENDENT-SEGMENTS")
	containsExtInf := strings.Contains(m3u8Content, "EXTINF")
	containsHttp := strings.Contains(m3u8Content, "http://")
	containsMk := strings.Contains(m3u8Content, `"Ret":20102,"Reason":"`)
	if (containsVersion && containsStream && !containsSegments) || (containsStream && containsDefaultVhost) || (containsStream && containsHttp) {
		log.Printf("访问 %s 成功, 包含 'EXT-X-VERSION' 和 'EXT-X-STREAM-INF _defaultVhost_'，不写入文件, 耗时: %v\n", url, duration)
	} else if cfg.DownloadTS && !containsStream && !containsMk {
		DownloadTS(ip, port, urlPath, cfg, successfulIPsCh)
	} else if (containsVersion && containsExtInf) || containsStream || containsMk || (containsVersion && containsSegments) {
		log.Printf("访问 %s 成功, 包含 'EXT-X-VERSION' 或 'EXT-X-STREAM-INF' 或 '秒开', 耗时: %v\n", url, duration)
		outputString := util.GenerateOutputString(ip, port, urlPath, serverHeader, cfg, duration, nil)
		trimmedOutput := strings.TrimSpace(outputString)
		if trimmedOutput != "" {
			successfulIPsCh <- trimmedOutput
		}
	}
}

// MkHTMLContent 检查HTML内容（独立请求版本）
func MkHTMLContent(ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)

	log.Printf("检查 %s 内容是否包含 'window.PAGE_PREFIX = \"player-\"' 或 'window.PAGE_JS = \"mylive.html.js\"'\n", url)

	client := GetHTTPClient(cfg)
	req, err := CreateHTTPRequest(url)
	if err != nil {
		log.Printf("创建请求失败: %v\n", err)
		return
	}
	req.Header = cfg.UAHeaders

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		log.Printf("请求 %s 失败: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		serverHeader := resp.Header.Get("Server")
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			log.Printf("读取 %s 响应体失败: %v\n", url, err)
			return
		}
		processHTMLBody(ip, port, urlPath, serverHeader, body, cfg, successfulIPsCh, duration)
	} else {
		log.Printf("请求 %s 失败, 状态码: %d, 耗时: %v\n", url, resp.StatusCode, duration)
	}
}

// MkHTMLBody 检查HTML内容（复用已有 body，避免重复请求）
func MkHTMLBody(ip string, port int, urlPath string, serverHeader string, body []byte, cfg *config.Config, successfulIPsCh chan<- string, duration time.Duration) {
	processHTMLBody(ip, port, urlPath, serverHeader, body, cfg, successfulIPsCh, duration)
}

func processHTMLBody(ip string, port int, urlPath string, serverHeader string, body []byte, cfg *config.Config, successfulIPsCh chan<- string, duration time.Duration) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)

	pageContent := string(body)
	containsPagePrefix := strings.Contains(pageContent, `window.PAGE_PREFIX = "player-"`)
	containsPageJS := strings.Contains(pageContent, `window.PAGE_JS = "mylive.html.js"`)
	containsRet := strings.Contains(pageContent, `"Ret":`)
	containsReason := strings.Contains(pageContent, `"Reason":`)
	containsExtInf := strings.Contains(pageContent, "EXTINF")
	containsVersion := strings.Contains(pageContent, "EXT-X-VERSION")
	if (containsPagePrefix && containsPageJS) || (containsRet && containsReason) || (containsExtInf && containsVersion) {
		log.Printf("访问 %s 成功, 包含 'window.PAGE_PREFIX = \"player-\"' 和 'window.PAGE_JS = \"mylive.html.js\"', 耗时: %v\n", url, duration)
		outputString := util.GenerateOutputString(ip, port, urlPath, serverHeader, cfg, duration, nil)
		trimmedOutput := strings.TrimSpace(outputString)
		if trimmedOutput != "" {
			successfulIPsCh <- trimmedOutput
		}
	} else if containsPagePrefix || containsPageJS || containsReason || containsRet {
		log.Printf("访问 %s 成功, 包含 'window.PAGE_PREFIX = \"player-\"' 或 'window.PAGE_JS = \"mylive.html.js\"'，不写入文件\n", url)
	} else if containsExtInf && containsVersion {
		// M3U8 内容在 HTML 中，交给 mpegurl 处理
		CheckMPEGURLBody(ip, port, urlPath, serverHeader, body, cfg, successfulIPsCh, duration)
	}
}
