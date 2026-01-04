package config

import (
	"os"
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