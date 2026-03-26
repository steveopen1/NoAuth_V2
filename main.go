package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"noauth/lib"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
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
	wayback bool
	targets string
	rate    int
	finger  bool
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
	flag.BoolVar(&wayback, "wayback", false, "查询Wayback Machine历史信息")
	flag.StringVar(&targets, "targets", "", "批量测试目标文件（每行一个URL）")
	flag.IntVar(&rate, "rate", 0, "每秒最大请求数（0=无限制）")
	flag.BoolVar(&finger, "finger", false, "启用WAF/CDN指纹识别")
	flag.Usage = usage
}

func checkFlags() {
	if timeout < 1 {
		fmt.Printf(lib.Yellow("[*] 超时时间设置为 %d，修正为最小值 1 秒\n"), timeout)
		timeout = 1
	}
	if t < 1 {
		fmt.Printf(lib.Yellow("[*] 并发线程设置为 %d，修正为最小值 1\n"), t)
		t = 1
	}

	if list && u != "" {
		fmt.Println("错误: -list 和 -u 不能同时使用，请选择其中一个。")
		os.Exit(1)
	}

	if r != "" {
		if _, err := os.Stat(r); os.IsNotExist(err) {
			fmt.Printf("错误: 数据包文件不存在: %s\n", r)
			os.Exit(1)
		}
		return
	}

	if targets != "" {
		if n == "" || a == "" {
			fmt.Println("错误: 批量测试需要指定 -n 和 -a 参数。")
			os.Exit(1)
		}
		return
	}

	if n == "" || a == "" {
		fmt.Println("错误: 缺少必要参数。请使用 -h 查看所需参数。")
		os.Exit(1)
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

	// 默认启用执行链路追踪
	lib.EnableTrace()

	if wayback {
		if u == "" {
			fmt.Println(lib.Red("[-] -wayback 需要配合 -u 参数使用"))
			os.Exit(0)
		}
		lib.InitHTTPClient(proxy, timeout)
		lib.PrintWaybackReport(u)
		os.Exit(0)
	}

	if finger {
		if u == "" {
			fmt.Println(lib.Red("[-] -finger 需要配合 -u 参数使用"))
			os.Exit(0)
		}
		lib.InitHTTPClient(proxy, timeout)
		baseURL := strings.TrimSuffix(u, "/")
		resp, err := lib.HttpClient.Get(baseURL)
		if err != nil {
			fmt.Printf(lib.Red("[-] 请求目标失败: %s\n"), err)
			os.Exit(0)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		lib.PrintFingerprintReport(u, resp, body)
		os.Exit(0)
	}

	checkFlags()

	if targets != "" {
		batchTestMode()
		return
	}

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
	lib.TraceCall("main", "InitHTTPClient", fmt.Sprintf("proxy=%s timeout=%d", proxy, timeout))

	if proxy != "" {
		fmt.Printf(lib.Blue("[+] 已设置 HTTP 代理: %s\n"), proxy)
	}
	fmt.Printf(lib.Blue("[+] HTTP 超时: %d 秒 | 并发线程: %d\n"), timeout, t)

	// 获取无鉴权接口基准（正向基线，用于双基线判定）
	lib.TraceCall("main", "FetchBaseline", "获取无鉴权接口基准")
	baseURL := strings.TrimSuffix(u, "/")
	noauthBaseline, err := lib.FetchBaseline(baseURL + n)
	if err != nil {
		fmt.Printf(lib.Yellow("[!] 获取无鉴权接口基准失败: %s，将使用降级判定模式\n"), err)
		noauthBaseline = lib.Baseline{}
		lib.TraceReturn("main", "FetchBaseline", "降级模式: 无NoAuth基线")
	} else {
		fmt.Printf(lib.Green("[+] 无鉴权接口 %s 基准: code=%d len=%d\n"), baseURL+n, noauthBaseline.Code, noauthBaseline.Len)
		lib.TraceReturn("main", "FetchBaseline", fmt.Sprintf("code=%d len=%d", noauthBaseline.Code, noauthBaseline.Len))
	}

	// 三阶段测试，收集结果（传入 noauth 基线供智能判定引擎使用）
	lib.TraceInfo("main", "三阶段测试", "开始执行")
	lib.TraceCall("main", "GetStart", "阶段一: GET 路径 Fuzz")
	getSheet, origCode, origLen, getHitPayloads := lib.GetStart(u, n, a, t, debug, noauthBaseline)
	lib.TraceReturn("main", "GetStart", fmt.Sprintf("完成: %d个命中", len(getHitPayloads)))

	lib.TraceCall("main", "PostStart", "阶段二: POST 路径 Fuzz")
	postSheet := lib.PostStart(u, n, a, t, debug, noauthBaseline, getHitPayloads)
	lib.TraceReturn("main", "PostStart", "完成")

	lib.TraceCall("main", "HeaderBypassStart", "阶段三: Header/Method 绕过")
	headerSheet := lib.HeaderBypassStart(u, n, a, t, debug, noauthBaseline)
	lib.TraceReturn("main", "HeaderBypassStart", "完成")

	// 统一导出到一个 Excel（三个 Sheet）
	lib.TraceCall("main", "ExportAllToExcel", "导出 Excel 格式")
	lib.ExportAllToExcel(u, []lib.SheetData{getSheet, postSheet, headerSheet})
	lib.TraceReturn("main", "ExportAllToExcel", "results.xlsx")

	// 同时导出 JSON 格式便于自动化分析
	lib.TraceCall("main", "ExportAllToJSON", "导出 JSON 格式")
	lib.ExportAllToJSON(u, []lib.SheetData{getSheet, postSheet, headerSheet})
	lib.TraceReturn("main", "ExportAllToJSON", "results.json")

	// 生成测试报告
	lib.TraceCall("main", "GenerateReport", "生成 Markdown 报告")
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
	lib.TraceReturn("main", "GenerateReport", "report.md")

	// 打印执行链路汇总
	lib.PrintExecutionChain()
	lib.PrintTraceSummary()
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

func batchTestMode() {
	if n == "" || a == "" {
		fmt.Println(lib.Red("[-] 批量测试需要指定 -n (无鉴权接口) 和 -a (鉴权接口)"))
		os.Exit(0)
	}

	file, err := os.Open(targets)
	if err != nil {
		fmt.Printf(lib.Red("[-] 打开目标文件失败: %s\n"), err)
		os.Exit(0)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				line = "http://" + line
			}
			urls = append(urls, line)
		}
	}

	if len(urls) == 0 {
		fmt.Println(lib.Red("[-] 未找到有效的目标URL"))
		os.Exit(0)
	}

	fmt.Printf(lib.Blue("[+] 批量测试模式: 加载了 %d 个目标\n"), len(urls))
	if rate > 0 {
		fmt.Printf(lib.Blue("[+] 请求速率限制: %d QPS\n"), rate)
	}

	lib.InitHTTPClient(proxy, timeout)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, t)
	varmu := &sync.Mutex{}
	successCount := 0
	failCount := 0

	for i, targetURL := range urls {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if rate > 0 {
				time.Sleep(time.Second / time.Duration(rate))
			}

			fmt.Printf(lib.Blue("[%d/%d] 测试目标: %s\n"), idx+1, len(urls), url)

			baseURL := strings.TrimSuffix(url, "/")
			noauthBaseline, err := lib.FetchBaseline(baseURL + n)
			if err != nil {
				fmt.Printf(lib.Yellow("[!] 获取无鉴权接口基准失败: %s\n"), err)
				noauthBaseline = lib.Baseline{}
			}

			getSheet, origCode, origLen, getHitPayloads := lib.GetStart(url, n, a, t, debug, noauthBaseline)
			postSheet := lib.PostStart(url, n, a, t, debug, noauthBaseline, getHitPayloads)
			headerSheet := lib.HeaderBypassStart(url, n, a, t, debug, noauthBaseline)

			lib.ExportAllToExcel(url, []lib.SheetData{getSheet, postSheet, headerSheet})
			lib.ExportAllToJSON(url, []lib.SheetData{getSheet, postSheet, headerSheet})

			meta := lib.ReportMeta{
				TargetURL:  url,
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

			varmu.Lock()
			successCount++
			varmu.Unlock()
		}(i, targetURL)
	}

	wg.Wait()
	fmt.Printf(lib.Green("\n[+] 批量测试完成: 成功 %d, 失败 %d\n"), successCount, failCount)
}
