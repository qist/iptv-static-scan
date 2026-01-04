package config

import (
	"os"
	"strings"
	_ "embed"
	"gopkg.in/yaml.v3"
)

// 配置结构体
type Config struct {
	Ports                []string            `yaml:"ports"`
	URLPaths             []string            `yaml:"urlPaths"`
	NonPortsPath         []string            `yaml:"non_ports_path"`
	MaxConcurrentRequest int                 `yaml:"maxConcurrentRequests"`
	SuccessfulIPsFile    string              `yaml:"successfulIPsFile"`
	UAHeaders            map[string][]string `yaml:"uaHeaders"`
	CIDRFile             string              `yaml:"cidrFile"`
	TimeOut              int                 `yaml:"timeOut"`
	DownSize             float64             `yaml:"downSize"`
	FileBufferSize       int                 `yaml:"filebufferSize"`
	DownloadTS           bool                `yaml:"download_ts"`
	Outputs              bool                `yaml:"outputs"`
	LogEnabled           bool                `yaml:"logEnabled"`
	LogTimeFile          string              `yaml:"LogTimeFile"`
	LogTime              int                 `yaml:"LogTime"`
	LogIpEnabled         bool                `yaml:"LogIpEnabled"`
	LogTimeEnabled       bool                `yaml:"LogTimeEnabled"`
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

//go:embed version
var versionFile string

// Version 是程序版本号，默认从 version 文件读取
// 可以在编译时通过 -ldflags 覆盖，例如:
// go build -ldflags "-X 'github.com/qist/iptv-static-scan/config.Version=v1.0.0'" .
var Version = ""

func init() {
	// 如果 Version 没被 ldflags 覆盖，则用 embed 文件内容
	if Version == "" {
		Version = strings.TrimSpace(versionFile)
	}
}
