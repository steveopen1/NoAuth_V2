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
	flag.Usage = usage
}

func checkFlags() {
	if list && u != "" {
		fmt.Println("错误: -list 和 -u 不能同时使用，请选择其中一个。")
		os.Exit(0)
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

	lib.GetStart(u, n, a, t, debug)
	lib.PostStart(u, n, a, t, debug)
	lib.HeaderBypassStart(u, n, a, t, debug)
}
