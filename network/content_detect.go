package network

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/qist/iptv-static-scan/config"
	"github.com/qist/iptv-static-scan/util"
)

// 检查MPEGURL内容
func CheckMPEGURLContent(ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)

	log.Printf("检查 %s 内容是否包含 'EXT-X-VERSION' 或者 'EXT-X-STREAM-INF'\n", url)

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
		serverHeader := resp.Header.Get("Server")
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("读取 %s 响应体失败: %v\n", url, err)
			return
		}

		m3u8Content := string(body)
		containsVersion := strings.Contains(m3u8Content, "EXT-X-VERSION")
		containsStream := strings.Contains(m3u8Content, "EXT-X-STREAM-INF")
		containsDefaultVhost := strings.Contains(m3u8Content, "_defaultVhost_")
		containsSegments := strings.Contains(m3u8Content, "EXT-X-INDEPENDENT-SEGMENTS")
		containsExtInf := strings.Contains(m3u8Content, "EXTINF")
		containsHttp := strings.Contains(m3u8Content, "http://")
		containsMk := strings.Contains(m3u8Content, `"Ret":20102,"Reason":"`)
		if (containsVersion && containsStream && !containsSegments) || (containsStream && containsDefaultVhost) || (containsStream && containsHttp) {
			log.Printf("访问 %s 成功, 包含 'EXT-X-VERSION' 和 'EXT-X-STREAM-INF _defaultVhost_'，不写入文件\n", url)
		} else if cfg.DownloadTS && !containsStream && !containsMk {
			DownloadTS(ip, port, urlPath, cfg, successfulIPsCh)
		} else if (containsVersion && containsExtInf) || containsStream || containsMk || (containsVersion && containsSegments) {
			log.Printf("访问 %s 成功, 包含 'EXT-X-VERSION' 或 'EXT-X-STREAM-INF' 或 '秒开'\n", url)
			outputString := ""
			outputString = util.GenerateOutputString(ip, port, urlPath, serverHeader, cfg)
			// 去除输出字符串的首尾空白字符
			trimmedOutput := strings.TrimSpace(outputString)
			// 在写入文件之前检查去除空白后的字符串是否为空
			if trimmedOutput != "" {
				successfulIPsCh <- trimmedOutput
			}
		}
	} else {
		log.Printf("请求 %s 失败, 状态码: %d\n", url, resp.StatusCode)
		return // 状态码不为200时直接返回
	}
}

func MkHTMLContent(ip string, port int, urlPath string, cfg *config.Config, successfulIPsCh chan<- string) {
	url := fmt.Sprintf("http://%s:%d/%s", ip, port, urlPath)

	log.Printf("检查 %s 内容是否包含 'window.PAGE_PREFIX = \"player-\"' 或 'window.PAGE_JS = \"mylive.html.js\"'\n", url)

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
		serverHeader := resp.Header.Get("Server")
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("读取 %s 响应体失败: %v\n", url, err)
			return
		}

		pageContent := string(body)
		containsPagePrefix := strings.Contains(pageContent, `window.PAGE_PREFIX = "player-"`)
		containsPageJS := strings.Contains(pageContent, `window.PAGE_JS = "mylive.html.js"`)
		containsRet := strings.Contains(pageContent, `"Ret":`)
		containsReason := strings.Contains(pageContent, `"Reason":`)
		containsExtInf := strings.Contains(pageContent, "EXTINF")
		containsVersion := strings.Contains(pageContent, "EXT-X-VERSION")
		// containsJson := strings.Contains(pageContent, `CCTV`)
		// containscore := strings.Contains(pageContent, `"code":401`)
		if (containsPagePrefix && containsPageJS) || (containsRet && containsReason) || (containsExtInf && containsVersion) {
			log.Printf("访问 %s 成功, 包含 'window.PAGE_PREFIX = \"player-\"' 和 'window.PAGE_JS = \"mylive.html.js\"'\n", url)
			outputString := ""
			outputString = util.GenerateOutputString(ip, port, urlPath, serverHeader, cfg)
			// 去除输出字符串的首尾空白字符
			trimmedOutput := strings.TrimSpace(outputString)
			// 在写入文件之前检查去除空白后的字符串是否为空
			if trimmedOutput != "" {
				successfulIPsCh <- trimmedOutput
			}
		} else if containsPagePrefix || containsPageJS || containsReason || containsRet {
			log.Printf("访问 %s 成功, 包含 'window.PAGE_PREFIX = \"player-\"' 或 'window.PAGE_JS = \"mylive.html.js\"'，不写入文件\n", url)
		}
	} else {
		log.Printf("请求 %s 失败, 状态码: %d\n", url, resp.StatusCode)
		return // 状态码不为200时直接返回
	}
}
