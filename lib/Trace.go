package lib

import (
	"fmt"
)

var traceLog []string
var traceEnabled = false

func EnableTrace() {
	traceEnabled = true
	traceLog = []string{}
	fmt.Println(Blue("[════════════════════════════════════════════════════════════════════]"))
	fmt.Println(Blue("[=] NoAuth_V2 执行链路追踪已启用"))
	fmt.Println(Blue("[════════════════════════════════════════════════════════════════════]"))
}

func DisableTrace() {
	traceEnabled = false
}

func TraceCall(module, function, data string) {
	if !traceEnabled {
		return
	}
	fmt.Printf("\033[36m[→]\033[0m \033[1m%s\033[0m :: %s\n", module, function)
	if data != "" {
		fmt.Printf("    └─ %s\n", data)
	}
}

func TraceReturn(module, function, result string) {
	if !traceEnabled {
		return
	}
	fmt.Printf("\033[32m[←]\033[0m \033[1m%s\033[0m :: %s\n", module, function)
	if result != "" {
		fmt.Printf("    └─ %s\n", result)
	}
}

func TraceInfo(module, function, info string) {
	if !traceEnabled {
		return
	}
	fmt.Printf("\033[33m[*]\033[0m \033[1m%s\033[0m :: %s\n", module, function)
	if info != "" {
		fmt.Printf("    └─ %s\n", info)
	}
}

func TraceError(module, function, err string) {
	if !traceEnabled {
		return
	}
	fmt.Printf("\033[31m[!]\033[0m \033[1m%s\033[0m :: %s\n", module, function)
	if err != "" {
		fmt.Printf("    └─ %s\n", err)
	}
}

func PrintTraceSummary() {
	if !traceEnabled {
		return
	}
	fmt.Println()
	fmt.Println(Blue("[════════════════════════════════════════════════════════════════════]"))
	fmt.Printf(Blue("[=] 执行事件汇总: %d 个事件\n"), len(traceLog))
	fmt.Println(Blue("[════════════════════════════════════════════════════════════════════]"))
}

func PrintExecutionChain() {
	if !traceEnabled {
		return
	}
	fmt.Println()
	fmt.Println("\033[36m┌──────────────────────────────────────────────────────────────────────┐\033[0m")
	fmt.Println("\033[36m[│] NoAuth_V2 模块调用链路图\033[0m")
	fmt.Println("\033[36m└──────────────────────────────────────────────────────────────────────┘\033[0m")
	fmt.Println()
	fmt.Println("  \033[1mmain()\033[0m")
	fmt.Println("  │")
	fmt.Println("  ├── \033[1mInitHTTPClient()\033[0m")
	fmt.Println("  │   └── 配置 HTTP 客户端（代理/TLS/超时/重试）")
	fmt.Println("  │")
	fmt.Println("  ├── \033[1mFetchBaseline()\033[0m")
	fmt.Println("  │   └── 获取无鉴权接口基准（正向基线）")
	fmt.Println("  │")
	fmt.Println("  ├── \033[1mGetStart()\033[0m \033[33m[阶段一: GET 路径 Fuzz]\033[0m")
	fmt.Println("  │   ├── poc.Summary() - 生成路径变异 payload (25种技术)")
	fmt.Println("  │   ├── 并发执行 GET 请求 (semaphore 限流)")
	fmt.Println("  │   ├── ClassifyResult() - 双基线智能判定引擎")
	fmt.Println("  │   └── ExportAllToExcel() - 导出 GET 测试结果")
	fmt.Println("  │")
	fmt.Println("  ├── \033[1mPostStart()\033[0m \033[33m[阶段二: POST 路径 Fuzz]\033[0m")
	fmt.Println("  │   ├── poc.Summary() - 复用 payload 列表")
	fmt.Println("  │   ├── selectPostPayloads() - 智能选择测试项")
	fmt.Println("  │   │   ├── GET 有命中 → 仅测试命中项")
	fmt.Println("  │   │   └── GET 无命中 → 探针检测后决定")
	fmt.Println("  │   ├── 并发执行 POST (Form + JSON) 请求")
	fmt.Println("  │   ├── ClassifyResult() - 双基线智能判定")
	fmt.Println("  │   └── ExportAllToExcel() - 导出 POST 测试结果")
	fmt.Println("  │")
	fmt.Println("  ├── \033[1mHeaderBypassStart()\033[0m \033[33m[阶段三: Header/Method 绕过]\033[0m")
	fmt.Println("  │   ├── \033[36mbuildIPSpoofCases()\033[0m - IP 伪造两阶段探测")
	fmt.Println("  │   │   ├── 阶段一: 粗筛 (ALL headers per IP) - 22请求")
	fmt.Println("  │   │   └── 阶段二: 精确定位 (per header) - N×40请求")
	fmt.Println("  │   ├── 路径重写 Header 绕过 (X-Original-URL 等)")
	fmt.Println("  │   ├── 方法覆盖 Header 绕过 (X-HTTP-Method-Override)")
	fmt.Println("  │   ├── Referer/Host/User-Agent 伪造")
	fmt.Println("  │   ├── 多头组合攻击 (XFF + RealIP + OriginIP)")
	fmt.Println("  │   ├── HTTP 方法智能探测 (OPTIONS → Allow)")
	fmt.Println("  │   └── ExportAllToExcel() - 导出 Header 测试结果")
	fmt.Println("  │")
	fmt.Println("  ├── \033[1mExportAllToExcel()\033[0m - 合并三个阶段到 results.xlsx")
	fmt.Println("  │")
	fmt.Println("  ├── \033[1mExportAllToJSON()\033[0m - 导出结构化 JSON (results.json)")
	fmt.Println("  │")
	fmt.Println("  └── \033[1mGenerateReport()\033[0m - 生成 Markdown 测试报告")
	fmt.Println()
	fmt.Println("\033[36m└──────────────────────────────────────────────────────────────────────┘\033[0m")
}
