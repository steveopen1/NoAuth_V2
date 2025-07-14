# NoAuth_V2-二开版
<img width="1721" height="580" alt="image" src="https://github.com/user-attachments/assets/7472e26f-1329-463e-ba64-75892c95fc40" />

二开内容如下:
- 丰富了示例及参数变更为中文
- 增加导出为xlsx文件，依据目标域名作为输出目录，最终将结果导出为该目录下
# NoAuth_V2
NoAuth 是一款用于动态生成可能绕过 Java 鉴权的 payload 并进行 fuzz 测试的工具，主要用于在代码审计和绕鉴权场景中节省时间
- 工具原地址
  https://github.com/wa1ki0g/NoAuth

### 示例用法
以下是一些使用示例，帮助你更好地理解如何使用这些参数：
#### 使用示例
<img width="1741" height="779" alt="image" src="https://github.com/user-attachments/assets/0d82ee25-aa82-44a8-9e04-0926cd34fef8" />
##### 导出结果示例
- 可自行在代码中修改导出目录（可以新增一个上级目录result，这里为了方便减少步骤）
<img width="887" height="492" alt="image" src="https://github.com/user-attachments/assets/3ce9e294-1beb-4549-bc56-a8ad992f1f5e" />
<img width="1015" height="357" alt="image" src="https://github.com/user-attachments/assets/1ce2892c-fa66-4646-b6ef-6b6c55e37818" />

### 用法说明
`Usage:  [-unat] [-u url] [-n interface without authentication] [-a interface An interface that requires authentication] [-t thread] [-debug choose start debug] [-h help]`：此为工具的使用说明，告知用户可以使用的参数选项。各参数含义如下：
### 参数文档
| 参数 | 类型 | 是否必填 | 默认值 | 描述 | 代码中对应位置 |
| --- | --- | --- | --- | --- | --- |
| `-u` | 字符串 | 是 | 无 | 目标 URL，必须包含 `http` 或 `https` 协议前缀。例如：`http://example.com`。 | 在 `main.go` 文件中，通过 `flag.StringVar(&u, "u", "", "A target url(Please add http or https)")` 定义。在 `main` 函数中会对该参数进行检查，如果未提供则会提示错误并退出程序。 |
| `-n` | 字符串 | 是 | 无 | 无需鉴权的接口地址，例如 `/login`、`/register` 等。 | 在 `main.go` 文件中，通过 `flag.StringVar(&n, "n", "", "An interface without authentication, such as /login")` 定义。同样在 `main` 函数中会检查该参数是否提供。 |
| `-a` | 字符串 | 是 | 无 | 需要鉴权的接口地址，例如 `/admin/adduser`。 | 在 `main.go` 文件中，通过 `flag.StringVar(&a, "a", "", "An interface that requires authentication, such as /admin/adduser")` 定义。在 `main` 函数中会检查该参数是否提供。 |
| `-t` | 整数 | 否 | 系统 CPU 核心数 | 线程数量，用于控制并发请求的数量。 | 在 `main.go` 文件中，通过 `flag.IntVar(&t, "t", runtime.NumCPU(), "Thread Num")` 定义，默认值为系统的 CPU 核心数。 |
| `-debug` | 整数 | 否 | 0 | 选择是否开启调试模式。传入 `1` 表示开启，开启后会输出所有请求的信息。 | 在 `main.go` 文件中，通过 `flag.IntVar(&debug, "debug", 0, "choose start debug, such -debug 1")` 定义。在 `lib/GetStart.go` 和 `lib/PostStart.go` 文件中会根据该参数的值决定是否输出详细的请求信息。 |
| `-h` | 无 | 否 | 无 | 显示帮助信息。 | 在 `main.go` 文件中，通过 `flag.BoolVar(&h, "h", false, "This help")` 定义。当用户传入 `-h` 参数时，程序会调用 `flag.Usage()` 函数输出帮助信息并退出。 |

#### 基本用法
```bash
noauth -n /login -a /admin/adduser -u http://localhost:8080/
```
此命令指定了无需鉴权的接口为 `/login`，需要鉴权的接口为 `/admin/adduser`，目标 URL 为 `http://localhost:8080/`。

#### 开启调试模式
```bash
noauth -n /login -a /admin/adduser -u http://localhost:8080/ -debug 1
```
在基本用法的基础上，添加了 `-debug 1` 参数，开启调试模式，会输出所有请求的详细信息。

#### 自定义线程数量
```bash
noauth -n /login -a /admin/adduser -u http://localhost:8080/ -t 20
```
此命令指定了线程数量为 20，用于控制并发请求的数量。

#### 查看帮助信息
```bash
noauth -h
```
该命令会输出工具的使用说明和参数选项的详细信息。

#### 结果导出功能
为了方便用户查看和分析测试结果，二次开发添加了将测试结果导出到 Excel 文件的功能。在 GetStart 和 PostStart 函数中，会将每个请求的 URL、响应长度和状态码等信息保存到一个二维数组中，最后使用 github.com/xuri/excelize/v2 库将数据写入 Excel 文件（get_results.xlsx 和 post_results.xlsx）。

# 编译
go build main.go

# 直接运行
go run .\main.go -h
