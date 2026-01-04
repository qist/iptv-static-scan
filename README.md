# iptv-static-scan

`iptv-static-scan` 是一个用于扫描 IPTV 流媒体服务的工具，可以扫描 IP 段和端口，寻找可访问的 IPTV 流媒体服务。

## 项目结构

```
iptv-static-scan/
├── cmd/
│   └── iptv-static-scan/
│       └── main.go
├── config/
│   └── config.go
├── scanner/
│   └── scanner.go
├── network/
│   ├── http_client.go
│   ├── download.go
│   └── content_detect.go
├── cidr/
│   ├── parser.go
│   ├── ip_range.go
│   ├── ip_generate.go
│   └── ipv6.go
├── domain/
│   └── domain.go
├── output/
│   ├── writer.go
│   └── cleanup.go
├── util/
│   ├── filename.go
│   └── port.go
├── go.mod
└── README.md
```

## 功能特点

- 扫描 IP 段（CIDR 格式）和 IP 范围
- 支持域名解析扫描
- 多端口扫描
- 自定义 URL 路径扫描
- 并发控制，可设置最大并发请求数
- 检测多种流媒体格式（FLV、MPEG URL、视频等）
- 支持检测特定服务（如 udpxy）
- 自动下载流媒体文件并验证大小
- 支持检测 M3U8 内容并下载 TS 文件
- 记录扫描结果到文件
- 支持自定义 User-Agent 头部
- 支持日志记录功能

## 安装

首先确保你已安装 Go 1.19 或更高版本，然后：

```bash
git clone https://github.com/your-repo/iptv-static-scan.git
cd iptv-static-scan
go mod tidy
go build ./main.go
```

## 配置

创建一个 `config.yaml` 配置文件：

```yaml
# 端口配置（支持范围和单个端口）
ports:
  - "554"
  - "80-85"
  - "8080"

# URL 路径配置
urlPaths:
  - "live"
  - "iptv/live"
  - "channel.m3u8"

# 非循环端口路径配置
non_ports_path:
  - "8080/live"

# 最大并发请求数
maxConcurrentRequests: 100

# 成功 IP 输出文件
successfulIPsFile: "successful_ips.txt"

# User-Agent 头部配置
uaHeaders:
  "User-Agent":
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# CIDR 文件路径
cidrFile: "cidr.txt"

# 超时时间（秒）
timeOut: 10

# 下载文件最小大小（MB）
downSize: 0.5

# 文件缓冲区大小
filebufferSize: 1000

# 是否下载 TS 文件
download_ts: true

# 输出格式控制
outputs: true

# 日志启用
logEnabled: true

# 日志时间文件
LogTimeFile: "log_time.txt"

# 日志时间间隔（分钟）
LogTime: 5

# 日志 IP 启用
LogIpEnabled: false

# 日志时间启用
LogTimeEnabled: true
```

## 使用方法

```bash
./main -config config.yaml
```

## 配置说明

- `ports`: 要扫描的端口列表，支持单个端口和范围（如 "80-85"）
- `urlPaths`: 要扫描的 URL 路径列表
- `non_ports_path`: 非循环端口的路径，格式为 "端口/路径"
- `maxConcurrentRequests`: 最大并发请求数，控制同时扫描的连接数
- `successfulIPsFile`: 成功扫描到的 IP 端口对输出文件
- `uaHeaders`: HTTP 请求头配置，用于模拟不同客户端
- `cidrFile`: 包含要扫描的 CIDR 段的文件
- `timeOut`: HTTP 请求超时时间（秒）
- `downSize`: 下载文件的最小大小（MB），用于验证流媒体内容
- `filebufferSize`: 文件缓冲区大小，影响写入性能
- `download_ts`: 是否下载 M3U8 中的 TS 文件
- `outputs`: 输出格式控制
- `logEnabled`: 是否启用日志
- `LogTimeFile`: 日志时间文件
- `LogTime`: 日志记录时间间隔（分钟）
- `LogIpEnabled`: 是否记录 IP 日志
- `LogTimeEnabled`: 是否启用时间日志

## CIDR 文件格式

CIDR 文件（如 `cidr.txt`）可以包含：

```
# 支持 CIDR 格式
192.168.1.0/24

# 支持 IP 范围
10.0.0.1-10.0.0.254

# 支持单个 IP
127.0.0.1
```

## 工作原理

1. 解析 CIDR 文件，生成 IP 地址列表
2. 根据配置的端口和 URL 路径生成扫描任务
3. 使用工作池模式并发执行扫描任务
4. 对每个 IP:端口:路径组合发起 HTTP 请求
5. 检查响应状态码和内容类型
6. 对成功响应进行进一步内容检测
7. 下载流媒体文件并验证大小
8. 将成功的结果写入输出文件

## 适用场景

- 扫描本地网络中的 IPTV 服务
- 寻找公开的流媒体服务
- 验证 IPTV 服务的可用性
- 网络安全审计

## 注意事项

- 请仅在授权范围内使用此工具
- 遵守相关法律法规
- 注意扫描频率，避免对目标网络造成过大压力

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。