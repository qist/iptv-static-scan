package util

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/qist/iptv-static-scan/config"
)

// 生成文件名
func GenerateFilename(urlPath string) string {
	var filename string
	if strings.Contains(urlPath, "?") {
		pathAndFilename := strings.Split(urlPath, "?")[0]
		directory, filenameWithExt := filepath.Split(pathAndFilename)
		filename = sanitizeFilename(filenameWithExt)
		if directory != "" {
			filename = filepath.Join(directory, filename)
			filename = strings.ReplaceAll(filename, "/", "")
			filename = strings.ReplaceAll(filename, "\\", "")
			filename = strings.ReplaceAll(filename, ":", "")
			filename = strings.ReplaceAll(filename, ".", "_")

		}
	} else {
		_, filename = filepath.Split(urlPath)
		filename = strings.ReplaceAll(filename, "/", "")
		filename = strings.ReplaceAll(filename, "\\", "")
		filename = strings.ReplaceAll(filename, ":", "")
		filename = strings.ReplaceAll(filename, ".", "_")
	}
	return filename
}

// 生成安全文件名
func sanitizeFilename(filename string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), r == '.', r == '_', r == '-':
			return r
		default:
			return -1
		}
	}, filename)
}

// 生成输出字符串
func GenerateOutputString(ip string, port int, urlPath string, serverHeader string, cfg *config.Config, duration time.Duration, speed *float64) string {
	if cfg.Outputs {
		if speed != nil {
			// 下载 TS 时输出耗时和速度
			if !cfg.LogEnabled {
				fmt.Printf("成功URL: Server:%s,http://%s:%d/%s, 耗时: %v, 速度: %.2f MB/s\n",
					serverHeader, ip, port, urlPath, duration, *speed)
			}
			return fmt.Sprintf("Server:%s,http://%s:%d/%s, 耗时: %v, 速度: %.2f MB/s\n",
				serverHeader, ip, port, urlPath, duration, *speed)
		} else {
			// 只是访问 URL，不下载 TS
			if !cfg.LogEnabled {
				fmt.Printf("成功URL: Server:%s,http://%s:%d/%s, 耗时: %v\n", serverHeader, ip, port, urlPath, duration)
			}
			return fmt.Sprintf("Server:%s,http://%s:%d/%s, 耗时: %v\n", serverHeader, ip, port, urlPath, duration)
		}
	}

	if !cfg.LogEnabled {
		if speed != nil {
			fmt.Printf("成功URL: Server:%s,http://%s:%d/%s, 耗时: %v, 速度: %.2f MB/s\n",
				serverHeader, ip, port, urlPath, duration, *speed)
		} else {
			fmt.Printf("成功URL: Server:%s,http://%s:%d/%s, 耗时: %v\n", serverHeader, ip, port, urlPath, duration)
		}
	}
	return fmt.Sprintf("%s:%d\n", ip, port)
}
