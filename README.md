<p align="center">
  <pre>
███    ██  ██████   █████  ██    ██ ████████ ██   ██
████   ██ ██    ██ ██   ██ ██    ██    ██    ██   ██
██ ██  ██ ██    ██ ███████ ██    ██    ██    ███████
██  ██ ██ ██    ██ ██   ██ ██    ██    ██    ██   ██
██   ████  ██████  ██   ██  ██████     ██    ██   ██
  </pre>
</p>

<p align="center">
  <strong>Java 鉴权绕过 Fuzz 测试工具</strong>
</p>

<p align="center">
  <a href="#快速开始">快速开始</a> •
  <a href="#功能特性">功能特性</a> •
  <a href="#参数说明">参数说明</a> •
  <a href="#使用示例">使用示例</a> •
  <a href="#项目结构">项目结构</a>
</p>

---

## 简介

NoAuth_V2 是一款用于动态生成鉴权绕过 Payload 并进行自动化 Fuzz 测试的安全工具。主要面向 **Java Web 应用**（Spring Security、Shiro、自研过滤器等）的鉴权机制，通过路径操纵、编码混淆、Header 注入等多种技术组合，检测目标接口是否存在未授权访问漏洞。

适用场景：渗透测试、代码审计、红队评估中的鉴权绕过验证环节。

> 基于 [wa1ki0g/NoAuth](https://github.com/wa1ki0g/NoAuth) 二次开发。

## 功能特性

### 三阶段测试流程

| 阶段 | 方法 | 输出文件 | 说明 |
|:---:|:---:|:---:|---|
| 1 | GET | `get_results.xlsx` | 对鉴权接口发送路径变异的 GET 请求 |
| 2 | POST | `post_results.xlsx` | 同时测试 Form-data 和 JSON 两种 Content-Type |
| 3 | Header/Method | `header_bypass_results.xlsx` | IP 伪造、路径重写、方法覆盖、智能 HTTP 方法探测 |

### Payload 覆盖范围

**路径操纵 (19 个生成模块)**

| 技术 | 示例 | 对应模块 |
|---|---|---|
| 路径穿越 | `..;/`、`../`、`%u002e%u002e/` | Pathtraversal |
| 分号注入 | `;/`、`/;//`、`;foo=bar/` | Pointgf、GFG、SxS |
| 点斜线插入 | `./`、`./././...` | Pointg、Pointgten |
| URL 编码混淆 | `%2e/`、`%2e%2e/`、`%2f` | Twoe、Twote、Zerod |
| 双重编码 | `%252f`、`%252e%252e%253b/` | DoubleEncode |
| Unicode 编码 | `%ef%bc%8f`、`%c0%af`、`%u002f` | UnicodeFull |
| 大小写变异 | `/Admin` → `/aDmin` | Middle |
| 后缀伪装 | `.js`、`.json`、`;.css`、`.wsdl` | Suffix |
| 双斜线 | `//` 路径规范化混淆 | Midg |
| 空格编码 | `%20/` 分隔符混淆 | KG |
| 查询参数污染 | `?`、`??`、`?debug=1`、`#` | QueryFragment |
| Tab/Null 注入 | `%09`、`%00`、`%0d%0a` | TabNull |
| 反斜杠混淆 | `\`、`%5c`、`..\;/` | Backslash |

**Header 绕过**

| 类型 | 数量 | 说明 |
|---|---|---|
| IP 伪造头 | 22 种 × 10 IP | X-Forwarded-For、X-Real-IP、True-Client-IP 等 |
| 路径重写头 | 3 种 | X-Original-URL、X-Rewrite-URL、X-Override-URL |
| 方法覆盖头 | 3 种 × 5 方法 | X-HTTP-Method-Override 等 |
| Referer 伪造 | 2 种 | 自身路径 / 根路径 |

**HTTP 方法智能探测**

```
目标响应 200 → 跳过方法探测（已可访问）
目标响应 401/403/405/302 → 发送 OPTIONS 请求
  ├─ Allow 头存在 → 按声明方法精准测试
  └─ Allow 头缺失 → 回退测试 PUT / PATCH / HEAD
```

### 工程化能力

- **结果导出** — 自动按目标域名创建目录，导出带格式的 Excel 文件
- **智能判定** — 自动标记"可能绕过"、"重定向"、"拒绝访问"、"长度差异"
- **结果去重** — 相同 URL/长度/状态码 的结果自动去重
- **进度显示** — 实时输出 `[N/Total]` 测试进度
- **代理支持** — `-proxy` 参数可将流量转发至 Burp Suite
- **TLS 兼容** — 自动跳过证书验证，支持自签名证书目标
- **超时控制** — `-timeout` 可配置请求超时，防止挂起
- **重定向保留** — 不自动跟随 302/301，保留原始鉴权响应
- **Windows 兼容** — 自动适配 CMD/PowerShell 颜色输出，修复冒号目录问题

## 快速开始

### 编译

```bash
git clone https://github.com/steveopen1/NoAuth_V2.git
cd NoAuth_V2
go mod tidy
go build -o noauth main.go
```

### 基本用法

```bash
./noauth -n /login -a /admin/adduser -u http://target.com/
```

参数含义:
- `-n` 无需鉴权的接口（作为对照基准）
- `-a` 需要鉴权的接口（测试目标）
- `-u` 目标 URL

## 参数说明

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|:---:|:---:|:---:|:---:|---|
| `-u` | string | 是 | - | 目标 URL，需包含 `http://` 或 `https://` |
| `-n` | string | 是 | - | 无需鉴权的接口路径，如 `/login` |
| `-a` | string | 是 | - | 需要鉴权的接口路径，如 `/admin/adduser` |
| `-t` | int | 否 | CPU 核心数 | 并发线程数 |
| `-debug` | int | 否 | 0 | 调试模式，`1` 输出所有请求详情 |
| `-proxy` | string | 否 | - | HTTP 代理地址，如 `http://127.0.0.1:8080` |
| `-timeout` | int | 否 | 15 | 请求超时（秒） |
| `-list` | bool | 否 | false | 仅生成 Payload 字典文件，不发送请求 |
| `-h` | - | 否 | - | 显示帮助信息 |

## 使用示例

```bash
# 基本测试
./noauth -n /login -a /admin/adduser -u http://target.com/

# 开启调试模式（输出所有请求）
./noauth -n /login -a /admin/adduser -u http://target.com/ -debug 1

# 20 线程 + Burp 代理
./noauth -n /login -a /admin/adduser -u http://target.com/ -t 20 -proxy http://127.0.0.1:8080

# 自定义超时
./noauth -n /login -a /admin/adduser -u https://target.com/ -timeout 30

# 仅生成 Payload 字典（配合 Burp Intruder 使用）
./noauth -n /login -a /admin/adduser -list
```

### 输出结果

测试完成后，在当前目录下生成以目标域名命名的文件夹：

```
target.com/
├── results.xlsx    # 测试结果（含三个 Sheet）
└── report.md       # 测试报告
```

> Windows 环境下端口号中的 `:` 自动替换为 `_`（如 `localhost_8080/`）。

**results.xlsx** 包含三个 Sheet：

| Sheet | 内容 | 列 |
|---|---|---|
| GET 测试 | GET 路径 Fuzz 结果 | URL, 响应长度, 状态码, 判定 |
| POST 测试 | POST Form+JSON Fuzz 结果 | URL, 响应长度, 状态码, 请求类型, 判定 |
| Header/Method 测试 | Header 绕过 + 方法探测结果 | 绕过技术, URL, 响应长度, 状态码, 判定 |

- "可能绕过" 和 "长度差异大" 行自动红色高亮
- 每个 Sheet 支持自动筛选

**report.md** 测试报告包含：

| 章节 | 内容 |
|---|---|
| 测试概要 | 目标地址、接口路径、原始响应基准、测试参数 |
| 测试维度 | 三阶段覆盖的技术列表和 Payload 数量统计 |
| 结果统计 | 按判定分类汇总 + 风险等级标注 |
| 疑似绕过详情 | 每个疑似绕过的 URL、方法、响应特征、绕过依据分析、curl 复现命令 |
| 测试结论 | 综合评估 + 后续建议 |

## 项目结构

```
NoAuth_V2/
├── main.go                  # 入口：参数解析、流程调度
├── go.mod                   # Go 模块定义
├── lib/
│   ├── Color.go             # 终端颜色输出（自动适配 Windows）
│   ├── color_windows.go     # Windows VT 模式启用
│   ├── color_unix.go        # Unix 平台兼容
│   ├── Dict.go              # 字典生成模式
│   ├── Export.go            # Excel 统一导出（三 Sheet 合一）
│   ├── Report.go            # report.md 报告生成
│   ├── GetStart.go          # GET 测试引擎
│   ├── PostStart.go         # POST 测试引擎
│   ├── HeaderBypass.go      # Header/Method 绕过引擎
│   ├── HttpClient.go        # 共享 HTTP 客户端
│   └── Logo.go              # Banner
└── poc/                     # Payload 生成模块（19 个）
    ├── Summary.go           # 模块编排 + 去重
    ├── Pathtraversal.go     # 路径穿越
    ├── Pointg.go            # ./ 插入
    ├── Pointgf.go           # ;/ 插入
    ├── Pointgten.go         # 长 ./ 链
    ├── Suffix.go            # 后缀伪装
    ├── Middle.go            # 中间编码 + 大小写变异
    ├── Midg.go              # 双斜线
    ├── KG.go                # 空格编码
    ├── GFG.go               # /;// 插入
    ├── SxS.go               # 分号路径混淆
    ├── Twoe.go              # %2e/ 编码
    ├── Twop.go              # 尾部 /.. 追加
    ├── Twote.go             # %2e%2e/ 编码
    ├── Zerod.go             # 多编码字符插入
    ├── QueryFragment.go     # 查询参数/片段污染
    ├── TabNull.go           # Tab/Null 字节注入
    ├── Backslash.go         # 反斜杠混淆
    ├── DoubleEncode.go      # 双重 URL 编码
    └── UnicodeFull.go       # Unicode 编码绕过
```

## 环境要求

- Go 1.21+
- 依赖：`github.com/xuri/excelize/v2`（`go mod tidy` 自动安装）

## 致谢

- 原始项目：[wa1ki0g/NoAuth](https://github.com/wa1ki0g/NoAuth)

## 免责声明

本工具仅供安全研究和授权测试使用。使用者应确保已获得目标系统的合法授权，对未授权系统进行测试属于违法行为。作者不对因使用本工具产生的任何后果承担责任。
