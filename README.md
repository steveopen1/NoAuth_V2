<p align="center">
  <pre>
████    ██  ██████   █████  ██    ██ ████████ ██   ██
█████   ██ ██    ██ ██   ██ ██    ██    ██    ██   ██
██ ██  ██ ██    ██ ███████ ██    ██    ██    ███████
██  ██ ██ ██    ██ ██   ██ ██    ██    ██    ██   ██
██   ████  ██████  ██   ██  ██████     ██    ██   ██
  </pre>
</p>

<p align="center">
  <strong>鉴权绕过 Fuzz 测试工具 v2.0</strong>
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

NoAuth_V2 是一款用于动态生成鉴权绕过 Payload 并进行自动化 Fuzz 测试的安全工具。主要面向 **Java Web 应用**（Spring Security、Shiro，自研过滤器等）的鉴权机制，通过路径操纵、编码混淆、Header 注入等多种技术组合，检测目标接口是否存在未授权访问漏洞。

适用场景：渗透测试、代码审计，红队评估中的鉴权绕过验证环节。

> 基于 [wa1ki0g/NoAuth](https://github.com/wa1ki0g/NoAuth) 二次开发。

## 功能特性

### 三阶段测试流程

| 阶段 | 方法 | 输出文件 | 说明 |
|:---:|:---:|:---:|---|
| 1 | GET | `results.xlsx` | 对鉴权接口发送路径变异的 GET 请求 |
| 2 | POST | `results.xlsx` | 同时测试 Form-data 和 JSON 两种 Content-Type |
| 3 | Header/Method | `results.xlsx` | IP 伪造、路径重写、方法覆盖、智能 HTTP 方法探测 |

### Payload 覆盖范围

**路径操纵 (25 个生成模块)**

| 技术 | 示例 | 对应模块 |
|---|---|---|
| 路径穿越 | `..;/`、`../`、`%u002e%u002e/` | Pathtraversal |
| 分号注入 | `;/`、`/;//`、`;foo=bar/` | Pointgf、GFG、SxS |
| 分号+Tab穿越 | `/;%09..;/`、`;%09`、`;a=1` | SemiTabTraversal |
| 点斜线插入 | `./`、`./././...` | Pointg、Pointg ten |
| URL 编码混淆 | `%2e/`、`%2e%2e/`、`%2f` | Twoe、Twote、Zerod |
| 双重编码 | `%252f`、`%252e%252e%253b/`、`%2e%2e%2f/` | DoubleEncode |
| Unicode 编码 | `%ef%bc%8f`、`%c0%af`、`%u002f` | UnicodeFull |
| 大小写变异 | 全大写/交替/首字母/末段变异 | Middle、PathCase |
| 后缀伪装 | `.js`、`.json`、`.css`、`.wsdl` | Suffix |
| 双斜线 | `//` 路径规范化混淆 | Midg |
| 空格编码 | `%20/` 分隔符混淆 | KG |
| 查询参数污染 | `?`、`??`、`?debug=1`、`#` | QueryFragment |
| Tab/Null 注入 | `%09`、`%00`、`%0d%0a` | TabNull |
| 反斜杠混淆 | `\`、`%5c`、`..\;/` | Backslash |
| CRLF 注入 | `%0d%0a`、Unicode CRLF 变体 | CRLFInjection |
| 路径末尾变异 | `/.`、`/..`、`%00`、`;/`、`/*` | EndPaths |
| 路径中间注入 | `/../`、`/.;/`、`/%00/`、`/%09/` | MidPaths |

**Header 绕过**

| 类型 | 数量 | 说明 |
|---|---|---|
| IP 伪造头 | 40+ 种 × 22 IP | X-Forwarded-For、X-Real-IP、Base-Url、Proxy-Host 等，含 IPv6/十六进制/八进制/短形式/scheme 前缀 |
| 路径重写头 | 5 种 | X-Original-URL、X-Rewrite-URL、X-Override-URL、X-Accel-Redirect、X-Forwarded-Path |
| 方法覆盖头 | 3 种 × 5 方法 | X-HTTP-Method-Override 等 |
| Verb-Case 切换 | 6 种 | gEt、GeT、GEt、gET 等大小写变体 |
| Referer 伪造 | 2 种 | 自身路径 / 根路径 |
| Host 头注入 | 8 种 | localhost、127.0.0.1、0.0.0.0、k8s Service Host |
| 协议/端口伪造 | 10 种 | X-Forwarded-Proto、X-Forwarded-Port、X-Forwarded-Scheme |
| User-Agent 伪装 | 5 种 | Googlebot、Bingbot、Yahoo Slurp、curl、AhrefsBot |
| 传输编码绕过 | 1 种 | Transfer-Encoding: chunked |
| Accept 头操纵 | 4 种 | JSON、HTML、XML、通配符 |
| HTTP/1.0 降级 | 1 种 | Via: 1.0 模拟协议降级 |
| TRACE/TRACK/CONNECT | 3 种 | HTTP 方法变体绕过 |
| Nginx 内部重定向 | 2 种 | X-Accel-Redirect 绕过前端 ACL |
| 多头组合攻击 | 6 种 | 同时注入多个绕过头（最多 8 头并发注入） |
| Hop-by-Hop 头利用 | 9 种 | Connection 头剥离 Cookie/Authorization/XFF 等鉴权头 |
| 自定义 HTTP 方法 | 9 种 | FOO、JEFF、PROPFIND、MKCOL 等非标准方法绕过 WAF |
| Spring 尾斜杠绕过 | 2 种 | antMatchers("/admin") 不匹配 "/admin/" |
| Spring 换行注入 | 4 种 | regexMatchers 的 %0a/%0d 正则绕过 |
| Spring 后缀模式 | 6 种 | .action/.do/.htm 后缀模式匹配绕过 |

**HTTP 方法智能探测**

```
目标响应 200 → 跳过方法探测（已可访问）
目标响应 401/403/405/302 → 发送 OPTIONS 请求
  ├─ Allow 头存在 → 按声明方法精准测试
  └─ Allow 头缺失 → 回退测试 PUT / PATCH / HEAD / TRACE
```

**双基线智能判定引擎**

```
正向基线: -n 指定的无鉴权接口响应（code + len + body 关键词）
拦截基线: -a 指定的鉴权接口原始响应（code + len）

判定逻辑:
┌─ 状态码从拦截(401/403/302)变为 200
│  ├─ 响应长度与正向基线相似度 >90% 且无登录特征 → 可能绕过(高)
│  ├─ 相似度 >70% 且无登录特征                   → 可能绕过(中)
│  └─ 响应含登录/错误关键词                       → 可能绕过(低)
├─ 302/301 重定向
│  ├─ Location 非登录路径 → 重定向(需关注)
│  └─ Location 为登录路径 → 重定向（正常拦截）
├─ 403/401 → 拒绝访问
├─ 同为 200 + 长度差异 > max(原始长度×20%, 50字节)
│  ├─ 更接近正向基线 → 长度差异大(高)
│  └─ 其他           → 长度差异大(中)
└─ 其他 → 状态码变化/长度差异小
```

### 工程化能力

- **结果导出** — 自动按目标域名创建目录，导出 Excel + JSON 双格式
- **双基线智能判定** — 同时参考无鉴权接口（正向基线）和鉴权接口（拦截基线）进行双向比较，支持置信度分级（高/中/低）、比例长度阈值、响应内容关键词检测，重定向目标分析
- **结果去重** — 两阶段去重（精确去重 + 语义去重），有效减少冗余
- **进度显示** — 实时输出 `[N/Total]` 测试进度 + 百分比进度条
- **代理支持** — `-proxy` 参数可将流量转发至 Burp Suite
- **TLS 兼容** — 自动跳过证书验证，支持自签名证书目标
- **超时控制** — `-timeout` 可配置请求超时，防止挂起
- **重定向保留** — 不自动跟随 302/301，保留原始鉴权响应
- **速率限制** — `-rate` 参数控制每秒最大请求数
- **批量测试** — `-targets` 参数支持从文件读取多个目标批量测试
- **中断恢复** — Session 管理支持测试中断后续传
- **WAF指纹识别** — `-finger` 参数自动识别目标 WAF/CDN 类型
- **Wayback查询** — `-wayback` 参数查询目标历史快照信息
- **执行链路追踪** — 默认开启，可视化模块调用链路
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
| `-t` | int | 否 | CPU 核心数 | 并发线程数（最小值 1） |
| `-debug` | int | 否 | 0 | 调试模式，`1` 输出所有请求详情 |
| `-proxy` | string | 否 | - | HTTP 代理地址，如 `http://127.0.0.1:8080` |
| `-timeout` | int | 否 | 15 | 请求超时秒数（最小值 1） |
| `-rate` | int | 否 | 0 | 每秒最大请求数（0=无限制） |
| `-targets` | string | 否 | - | 批量测试目标文件（每行一个 URL） |
| `-r` | string | 否 | - | 数据包文件路径（支持 RAW HTTP 和 cURL 格式） |
| `-m` | string | 否 | bypass | Fuzz 模式：bypass(401/403绕过) 或 logic(逻辑漏洞测试) |
| `-wayback` | bool | 否 | false | 查询 Wayback Machine 历史信息 |
| `-finger` | bool | 否 | false | 启用 WAF/CDN 指纹识别 |
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

# 自定义超时 + 速率限制
./noauth -n /login -a /admin/adduser -u https://target.com/ -timeout 30 -rate 50

# 批量测试（目标列表在 targets.txt）
./noauth -targets targets.txt -n /login -a /admin -rate 10

# 仅生成 Payload 字典（配合 Burp Intruder 使用）
./noauth -n /login -a /admin/adduser -list

# RequestFuzz 模式（自定义数据包文件）
./noauth -r request.txt -t 20

# WAF/CDN 指纹识别
./noauth -finger -u http://target.com/

# Wayback Machine 历史查询
./noauth -wayback -u http://target.com/
```

### 输出结果

测试完成后，在当前目录下生成以目标域名命名的文件夹：

```
target.com/
├── results.xlsx    # 测试结果（含三个 Sheet + 高亮标注）
├── results.json   # JSON 格式结果（便于自动化分析）
└── report.md      # Markdown 测试报告
```

> Windows 环境下端口号中的 `:` 自动替换为 `_`（如 `localhost_8080/`）。

**results.xlsx** 包含三个 Sheet：

| Sheet | 内容 | 列 |
|---|---|---|
| GET 测试 | GET 路径 Fuzz 结果 | URL, 响应长度, 状态码, 判定, curl复现命令 |
| POST 测试 | POST Form+JSON Fuzz 结果 | URL, 响应长度, 状态码, 请求类型, 判定, curl复现命令 |
| Header/Method 测试 | Header 绕过 + 方法探测结果 | 绕过技术, URL, 响应长度, 状态码, 判定, curl复现命令 |

- "可能绕过" 和 "长度差异大" 行自动红色高亮
- 每个 Sheet 支持自动筛选

**results.json** 结构化输出：

```json
[
  {
    "sheet": "GET 测试",
    "url": "http://target.com/..;/admin",
    "length": 1234,
    "status_code": 200,
    "classification": "可能绕过(高)",
    "curl_cmd": "curl -k -v \"http://target.com/..;/admin\"",
    "is_high_risk": true
  }
]
```

**report.md** 测试报告包含：

| 章节 | 内容 |
|---|
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
│   ├── Classify.go          # 双基线智能判定引擎（置信度分级）
│   ├── Color.go             # 终端颜色输出（自动适配 Windows）
│   ├── color_windows.go     # Windows VT 模式启用
│   ├── color_unix.go        # Unix 平台兼容
│   ├── Dict.go              # 字典生成模式
│   ├── Export.go            # Excel + JSON 统一导出
│   ├── Report.go            # report.md 报告生成
│   ├── GetStart.go          # GET 测试引擎
│   ├── PostStart.go         # POST 测试引擎
│   ├── HeaderBypass.go      # Header/Method 绕过引擎
│   ├── HttpClient.go        # 共享 HTTP 客户端（重试+超时）
│   ├── RequestParser.go     # RAW HTTP / cURL 格式解析
│   ├── FuzzVariants.go      # 通用 Fuzz 变体生成
│   ├── Fingerprint.go       # WAF/CDN 指纹识别（15+ 种）
│   ├── Session.go           # 测试会话保存与恢复
│   ├── ProgressBar.go       # 进度条可视化
│   ├── Trace.go             # 执行链路追踪（默认开启）
│   ├── Wayback.go          # Wayback Machine 查询
│   └── Logo.go              # Banner
└── poc/                     # Payload 生成模块（25 个）
    ├── Summary.go           # 模块编排 + 两阶段去重
    ├── Pathtraversal.go     # 路径穿越
    ├── Pointg.go            # ./ 插入
    ├── Pointgf.go           # ;/ 插入
    ├── Pointgten.go         # 长 ./ 链
    ├── Suffix.go            # 后缀伪装
    ├── Middle.go           # 中间编码 + 大小写变异
    ├── Midg.go             # 双斜线
    ├── KG.go                # 空格编码
    ├── GFG.go              # /;// 插入
    ├── SxS.go              # 分号路径混淆
    ├── Twoe.go             # %2e/ 编码
    ├── Twop.go             # 尾部 /.. 追加
    ├── Twote.go            # %2e%2e/ 编码
    ├── Zerod.go            # 多编码字符插入
    ├── QueryFragment.go    # 查询参数/片段污染
    ├── TabNull.go          # Tab/Null 字节注入
    ├── Backslash.go        # 反斜杠混淆
    ├── DoubleEncode.go     # 双重 URL 编码
    ├── UnicodeFull.go      # Unicode 编码绕过
    ├── SemiTabTraversal.go # ;%09..;/ 穿越模式
    ├── PathCase.go         # 路径大小写系统变异
    ├── CRLFInjection.go    # CRLF 注入
    ├── EndPaths.go         # 路径末尾变异
    └── MidPaths.go         # 路径中间注入
```

## 环境要求

- Go 1.21+
- 依赖：`github.com/xuri/excelize/v2`（`go mod tidy` 自动安装）

## 更新日志

### v2.0.0 (2026-03-25)

**新增功能：**
- JSON 格式导出（便于自动化分析）
- TRACE/TRACK/CONNECT HTTP 方法测试
- 双编码路径变体（`%2e%2e%2f/`）
- Wayback Machine 历史查询
- 批量测试模式（`-targets`）
- 请求速率限制（`-rate`）
- 自定义 Payload 导入支持
- 进度条可视化
- 测试会话中断恢复
- WAF/CDN 指纹识别（15+ 种）
- 执行链路追踪（默认开启）

**Bug 修复：**
- 修复 JSON 登录页检测误判
- 修复语义去重逻辑缺陷
- 修复 URL 替换影响长度计算
- 修复 Fuzz 变体 URL 解析失败
- 添加 timeout/线程参数边界校验

## 致谢

- 原始项目：[wa1ki0g/NoAuth](https://github.com/wa1ki0g/NoAuth)
- 参考项目：[iamj0ker/bypass-403](https://github.com/iamj0ker/bypass-403)
- 参考项目：[devploit/nomore403](https://github.com/devploit/nomore403)

## 免责声明

本工具仅供安全研究和授权测试使用。使用者应确保已获得目标系统的合法授权，对未授权系统进行测试属于违法行为。作者不对因使用本工具产生的任何后果承担责任。
