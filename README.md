# NoAuth_V2-二开版

# NoAuth_V2
二开内容如下:
- 丰富了示例及参数变更为中文
- 增加导出为xlsx文件，依据目标域名作为输出目录，最终将结果导出为该目录下
- 新增共享 HTTP 客户端，支持代理、超时配置、跳过 TLS 证书验证
- 禁止自动跟随重定向（302/301 本身是有意义的鉴权信号）
- 增加进度显示，实时展示测试进度
- 增加结果智能判定列（可能绕过、重定向、拒绝访问等）
- 导出结果自动去重
- 修复废弃 API 使用（ioutil、rand.Seed）

# NoAuth_V2
NoAuth 是一款用于动态生成可能绕过 Java 鉴权的 payload 并进行 fuzz 测试的工具，主要用于在代码审计和绕鉴权场景中节省时间
- 工具原地址
  https://github.com/wa1ki0g/NoAuth

### 示例用法
以下是一些使用示例，帮助你更好地理解如何使用这些参数：

### 用法说明
`Usage:  [-unat] [-u url] [-n interface without authentication] [-a interface An interface that requires authentication] [-t thread] [-debug choose start debug] [-h help]`：此为工具的使用说明，告知用户可以使用的参数选项。各参数含义如下：

### 参数文档
| 参数 | 类型 | 是否必填 | 默认值 | 描述 |
| --- | --- | --- | --- | --- |
| `-u` | 字符串 | 是 | 无 | 目标 URL，必须包含 `http` 或 `https` 协议前缀。 |
| `-n` | 字符串 | 是 | 无 | 无需鉴权的接口地址，例如 `/login`、`/register` 等。 |
| `-a` | 字符串 | 是 | 无 | 需要鉴权的接口地址，例如 `/admin/adduser`。 |
| `-t` | 整数 | 否 | 系统 CPU 核心数 | 线程数量，用于控制并发请求的数量。 |
| `-debug` | 整数 | 否 | 0 | 开启调试模式。传入 `1` 表示开启，输出所有请求信息。 |
| `-proxy` | 字符串 | 否 | 无 | 设置 HTTP 代理，例如 `http://127.0.0.1:8080`。 |
| `-timeout` | 整数 | 否 | 15 | HTTP 请求超时时间（秒）。 |
| `-list` | 布尔 | 否 | false | 字典生成模式，用于生成 payload 字典文件。 |
| `-h` | 无 | 否 | 无 | 显示帮助信息。 |

#### 基本用法
```bash
noauth -n /login -a /admin/adduser -u http://localhost:8080/
```

#### 开启调试模式
```bash
noauth -n /login -a /admin/adduser -u http://localhost:8080/ -debug 1
```

#### 自定义线程数量
```bash
noauth -n /login -a /admin/adduser -u http://localhost:8080/ -t 20
```

#### 使用代理
```bash
noauth -n /login -a /admin/adduser -u http://localhost:8080/ -proxy http://127.0.0.1:8080
```

#### 设置超时时间
```bash
noauth -n /login -a /admin/adduser -u http://localhost:8080/ -timeout 30
```

#### 查看帮助信息
```bash
noauth -h
```

#### 结果导出功能
测试结果自动导出到 Excel 文件（get_results.xlsx 和 post_results.xlsx）。
导出目录以目标域名命名，例如目标为 `http://localhost:8080/` 时，结果文件将保存在 `localhost:8080/` 目录下。

Excel 文件包含以下列：
- **URL**: 测试的完整 URL
- **响应长度**: 响应体长度
- **状态码**: HTTP 状态码
- **请求类型**: GET / POST-Form / POST-Json（POST 结果文件）
- **判定**: 自动分类结果（可能绕过、重定向、拒绝访问、长度差异大/小等）

# 编译
```bash
go mod tidy
go build -o noauth main.go
```

# 直接运行
```bash
go run main.go -h
```
