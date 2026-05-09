package network

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/qist/iptv-static-scan/config"
)

var (
	globalClient     *http.Client
	globalTransport  *http.Transport
	globalClientOnce sync.Once
	globalClientMu   sync.Mutex
)

// InitHTTPClient 初始化全局 HTTP 客户端（整个进程只创建一次 Transport）
func InitHTTPClient(cfg *config.Config) {
	globalClientMu.Lock()
	defer globalClientMu.Unlock()

	// 如果已初始化且配置未变，跳过
	if globalClient != nil {
		return
	}

	globalClientOnce.Do(func() {
		globalTransport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   time.Duration(cfg.TimeOut) * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          10000,
			MaxIdleConnsPerHost:   100,
			MaxConnsPerHost:       0, // 不限制每 host 总连接数
			DisableKeepAlives:     false,
		}

		checkRedirect := func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			if len(via) > 0 {
				lastRequest := via[len(via)-1]
				if lastRequest.URL.Scheme == "http" && req.URL.Scheme == "https" {
					logRedirectToHTTPS(lastRequest.URL.String(), req.URL.String())
					return fmt.Errorf("redirected to HTTPS")
				}
			}
			return nil
		}

		globalClient = &http.Client{
			Timeout:       time.Duration(cfg.TimeOut) * time.Second,
			Transport:     globalTransport,
			CheckRedirect: checkRedirect,
		}
	})
}

// GetHTTPClient 获取全局共享的 HTTP 客户端（懒初始化）
func GetHTTPClient(cfg *config.Config) *http.Client {
	InitHTTPClient(cfg)
	return globalClient
}

// CloseIdleConnections 关闭空闲连接（程序退出时调用）
func CloseIdleConnections() {
	globalClientMu.Lock()
	defer globalClientMu.Unlock()
	if globalTransport != nil {
		globalTransport.CloseIdleConnections()
	}
}

// CreateHTTPClient 保留旧接口兼容，但返回全局共享客户端
func CreateHTTPClient(cfg *config.Config) *http.Client {
	return GetHTTPClient(cfg)
}

// 创建并返回一个HTTP GET请求
func CreateHTTPRequest(url string) (*http.Request, error) {
	return http.NewRequest("GET", url, nil)
}

func logRedirectToHTTPS(fromURL string, toURL string) {
	logMessage := strings.TrimSpace(fmt.Sprintf("重定向到 HTTPS: %s -> %s\n", fromURL, toURL))
	log.Println(logMessage)
}
