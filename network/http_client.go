package network

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/qist/iptv-static-scan/config"
)

func CreateHTTPClient(cfg *config.Config) *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(cfg.TimeOut) * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true, // 启用 Happy Eyeballs
		}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
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

	client := &http.Client{
		Timeout:       time.Duration(cfg.TimeOut) * time.Second,
		Transport:     tr,
		CheckRedirect: checkRedirect,
	}

	// 在程序退出时释放空闲连接
	defer tr.CloseIdleConnections()

	return client
}

// 创建并返回一个HTTP GET请求
func CreateHTTPRequest(url string) (*http.Request, error) {
	return http.NewRequest("GET", url, nil)
}

func logRedirectToHTTPS(fromURL string, toURL string) {
	logMessage := strings.TrimSpace(fmt.Sprintf("重定向到 HTTPS: %s -> %s\n", fromURL, toURL))
	// 记录日志
	log.Println(logMessage)
}
