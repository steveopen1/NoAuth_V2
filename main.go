package main

import (
	"flag"
	"fmt"
	"noauth/lib"
	"os"
	"runtime"
	"strings"
)

var (
	u       string
	n       string
	t       int
	h       bool
	a       string
	debug   int
	list    bool
	proxy   string
	timeout int
	r       string
	m       string
)

func init() {
	flag.BoolVar(&h, "h", false, "显示帮助信息")
	flag.StringVar(&u, "u", "", "目标 URL（请添加 http 或 https 协议前缀）")
	flag.StringVar(&n, "n", "", "无需鉴权的接口，例如 /login")
	flag.StringVar(&a, "a", "", "需要鉴权的接口，例如 /admin/adduser")
	flag.IntVar(&t, "t", runtime.NumCPU(), "并发线程数量")
	flag.IntVar(&debug, "debug", 0, "开启调试模式，传入 1 启用，例如 -debug 1")
	flag.BoolVar(&list, "list", false, "字典生成模式，用于生成 payload 字典")
	flag.StringVar(&proxy, "proxy", "", "设置 HTTP 代理（例如 http://127.0.0.1:8080）")
	flag.IntVar(&timeout, "timeout", 15, "HTTP 请求超时时间（秒）")
	flag.StringVar(&r, "r", "", "数据包文件路径（支持 RAW HTTP 格式和 cURL 格式）")
	flag.StringVar(&m, "m", "bypass", "fuzz 模式：bypass(401/403绕过) 或 logic(逻辑漏洞测试)")
	flag.Usage = usage
}

func checkFlags() {
	if list && u != "" {
		fmt.Println("错误: -list 和 -u 不能同时使用，请选择其中一个。")
		os.Exit(0)
	}

	if r != "" {
		if _, err := os.Stat(r); os.IsNotExist(err) {
			fmt.Printf("错误: 数据包文件不存在: %s\n", r)
			os.Exit(0)
		}
		return
	}

	if n == "" || a == "" {
		fmt.Println("错误: 缺少必要参数。请使用 -h 查看所需参数。")
		os.Exit(0)
	}

	if !list && (u == "") {
		fmt.Println("错误: 缺少必要参数。请使用 -h 查看所需参数。")
		os.Exit(0)
	}

}

func usage() {
	fmt.Fprintf(os.Stderr, `noauth version: 2.0.0
用法:  [-unat] [-u 目标URL] [-n 无需鉴权的接口] [-a 需要鉴权的接口] [-t 线程数] [-debug 调试模式] [-h 帮助]

数据包Fuzz模式:
  noauth -r request.txt
  noauth -r request.txt -debug 1
  noauth -r request.txt -t 20

示例:
  noauth -n /login -a /admin/adduser -u http://localhost:8080/
  noauth -n /login -a /admin/adduser -u http://localhost:8080/ -debug 1
  noauth -n /login -a /admin/adduser -u http://localhost:8080/ -t 20
  noauth -n /login -a /admin/adduser -u http://localhost:8080/ -proxy http://127.0.0.1:8080
  noauth -n /login -a /admin/adduser -u http://localhost:8080/ -timeout 30
  noauth -n /login -a /admin/adduser -list

参数说明:
`)
	flag.PrintDefaults()
}

func main() {
	lib.Logo()
	flag.Parse()

	if h {
		flag.Usage()
		os.Exit(0)
	}

	checkFlags()

	if r != "" {
		requestFuzzMode()
		return
	}

	if list {
		lib.Dict(n, a)
		os.Exit(0)
	}

	res1 := strings.Contains(u, "http://")
	res2 := strings.Contains(u, "https://")

	if !res1 && !res2 {
		fmt.Println(lib.Red("[-] 请为 URL 添加 http 或 https 协议前缀！"))
		os.Exit(0)
	}

	// 初始化共享 HTTP 客户端（支持代理、超时、跳过 TLS 验证、禁止自动重定向）
	lib.InitHTTPClient(proxy, timeout)

	if proxy != "" {
		fmt.Printf(lib.Blue("[+] 已设置 HTTP 代理: %s\n"), proxy)
	}
	fmt.Printf(lib.Blue("[+] HTTP 超时: %d 秒 | 并发线程: %d\n"), timeout, t)

	// 获取无鉴权接口基准（正向基线，用于双基线判定）
	baseURL := strings.TrimSuffix(u, "/")
	noauthBaseline, err := lib.FetchBaseline(baseURL + n)
	if err != nil {
		fmt.Printf(lib.Yellow("[!] 获取无鉴权接口基准失败: %s，将使用降级判定模式\n"), err)
		noauthBaseline = lib.Baseline{}
	} else {
		fmt.Printf(lib.Green("[+] 无鉴权接口 %s 基准: code=%d len=%d\n"), baseURL+n, noauthBaseline.Code, noauthBaseline.Len)
	}

	// 三阶段测试，收集结果（传入 noauth 基线供智能判定引擎使用）
	getSheet, origCode, origLen, getHitPayloads := lib.GetStart(u, n, a, t, debug, noauthBaseline)
	postSheet := lib.PostStart(u, n, a, t, debug, noauthBaseline, getHitPayloads)
	headerSheet := lib.HeaderBypassStart(u, n, a, t, debug, noauthBaseline)

	// 统一导出到一个 Excel（三个 Sheet）
	lib.ExportAllToExcel(u, []lib.SheetData{getSheet, postSheet, headerSheet})

	// 同时导出 JSON 格式便于自动化分析
	lib.ExportAllToJSON(u, []lib.SheetData{getSheet, postSheet, headerSheet})

	// 生成测试报告
	meta := lib.ReportMeta{
		TargetURL:  u,
		NoAuth:     n,
		Auth:       a,
		Threads:    t,
		Timeout:    timeout,
		Proxy:      proxy,
		Debug:      debug,
		OrigCode:   origCode,
		OrigLen:    origLen,
		NoAuthCode: noauthBaseline.Code,
		NoAuthLen:  noauthBaseline.Len,
	}
	lib.GenerateReport(meta, getSheet, postSheet, headerSheet)
}

func requestFuzzMode() {
	lib.InitHTTPClient(proxy, timeout)

	fmt.Printf(lib.Blue("[+] HTTP 超时: %d 秒 | 并发线程: %d\n"), timeout, t)
	fmt.Printf(lib.Blue("[+] Fuzz 模式: %s\n"), m)
	fmt.Printf(lib.Blue("[+] 数据包文件: %s\n"), r)

	fuzzSheet := lib.RequestFuzzStart(r, t, debug, nil)

	filename := lib.ExportSingleSheetToExcel(r, fuzzSheet)
	if filename != "" {
		fmt.Printf(lib.Green("[+] 结果已保存: %s\n"), filename)
	}

	jsonFilename := lib.ExportSingleSheetToJSON(r, fuzzSheet)
	if jsonFilename != "" {
		fmt.Printf(lib.Green("[+] JSON 结果已保存: %s\n"), jsonFilename)
	}
}
