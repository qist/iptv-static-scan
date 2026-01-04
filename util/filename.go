package util

import (
	"fmt"
	"path/filepath"
	"strings"
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
func GenerateOutputString(ip string, port int, urlPath string, serverHeader string, cfg *config.Config) string {
	if cfg.Outputs {
		if !cfg.LogEnabled {
			fmt.Printf("成功URL: Server:%s,http://%s:%d/%s\n", serverHeader, ip, port, urlPath)
		}
		return fmt.Sprintf(" Server:%s,http://%s:%d/%s\n", serverHeader, ip, port, urlPath)
	}
	if !cfg.LogEnabled {
		fmt.Printf("成功IP及端口: Server:%s,http://%s:%d/%s\n", serverHeader, ip, port, urlPath)
	}
	return fmt.Sprintf("%s:%d\n", ip, port)
}
