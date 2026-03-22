package lib

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReportMeta 测试元信息
type ReportMeta struct {
	TargetURL  string
	NoAuth     string
	Auth       string
	Threads    int
	Timeout    int
	Proxy      string
	Debug      int
	OrigCode   int
	OrigLen    int
	NoAuthCode int
	NoAuthLen  int
}

// GenerateReport 根据所有测试结果生成 report.md
func GenerateReport(meta ReportMeta, getSheet, postSheet, headerSheet SheetData) {
	dir := GetOutputDir(meta.TargetURL)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf(Red("[-] 创建报告目录失败: %s\n"), err)
		return
	}

	filePath := filepath.Join(dir, "report.md")

	var sb strings.Builder

	// ======== 标题 ========
	sb.WriteString("# NoAuth_V2 鉴权绕过测试报告\n\n")
	sb.WriteString("---\n\n")

	// ======== 测试概要 ========
	sb.WriteString("## 1. 测试概要\n\n")
	sb.WriteString("| 项目 | 值 |\n")
	sb.WriteString("|---|---|\n")
	sb.WriteString(fmt.Sprintf("| 目标地址 | `%s` |\n", meta.TargetURL))
	sb.WriteString(fmt.Sprintf("| 无鉴权接口（基准） | `%s` |\n", meta.NoAuth))
	sb.WriteString(fmt.Sprintf("| 鉴权接口（目标） | `%s` |\n", meta.Auth))
	sb.WriteString(fmt.Sprintf("| 鉴权接口原始响应 | code=%d, len=%d |\n", meta.OrigCode, meta.OrigLen))
	if meta.NoAuthCode > 0 {
		sb.WriteString(fmt.Sprintf("| 无鉴权接口基准响应 | code=%d, len=%d |\n", meta.NoAuthCode, meta.NoAuthLen))
	}
	sb.WriteString(fmt.Sprintf("| 并发线程 | %d |\n", meta.Threads))
	sb.WriteString(fmt.Sprintf("| 超时时间 | %d 秒 |\n", meta.Timeout))
	if meta.Proxy != "" {
		sb.WriteString(fmt.Sprintf("| 代理 | `%s` |\n", meta.Proxy))
	}
	sb.WriteString(fmt.Sprintf("| 判定引擎 | 双基线智能判定 v2（比例阈值 + 内容分析 + 置信度） |\n"))
	sb.WriteString(fmt.Sprintf("| 测试时间 | %s |\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("\n")

	// ======== 判定引擎说明 ========
	sb.WriteString("### 判定引擎原理\n\n")
	sb.WriteString("本次测试使用双基线智能判定引擎，核心逻辑如下：\n\n")
	sb.WriteString("| 置信度 | 判定条件 |\n")
	sb.WriteString("|:---:|---|\n")
	sb.WriteString("| **高** | 状态码从拦截变为200 + 响应长度与无鉴权接口相似度>90% + 无登录页特征 |\n")
	sb.WriteString("| **中** | 状态码变为200 + 相似度>70%，或无鉴权基线不可用 |\n")
	sb.WriteString("| **低** | 状态码变为200 但响应含登录/错误页面关键词 |\n")
	sb.WriteString("| 重定向(需关注) | 重定向到非登录路径（可能是绕过后的业务跳转） |\n")
	sb.WriteString("\n")

	// ======== 测试维度 ========
	sb.WriteString("## 2. 测试维度\n\n")
	sb.WriteString("本次测试覆盖以下三个阶段：\n\n")
	sb.WriteString("| 阶段 | 方法 | Payload 数量 | 异常结果数 |\n")
	sb.WriteString("|:---:|:---:|:---:|:---:|\n")
	sb.WriteString(fmt.Sprintf("| 阶段一 | GET 路径 Fuzz | %d 个 Payload | %d 条异常 |\n",
		countTotal(getSheet), len(getSheet.Data)))
	sb.WriteString(fmt.Sprintf("| 阶段二 | POST 路径 Fuzz (Form+JSON) | %d 个 Payload | %d 条异常 |\n",
		countTotal(postSheet), len(postSheet.Data)))
	sb.WriteString(fmt.Sprintf("| 阶段三 | Header/Method 绕过 | %d 个测试用例 | %d 条异常 |\n",
		countTotal(headerSheet), len(headerSheet.Data)))
	sb.WriteString("\n")

	sb.WriteString("**路径 Fuzz 技术覆盖：**\n\n")
	sb.WriteString("- 路径穿越 (`..;/`, `../`, `%u002e%u002e/`)\n")
	sb.WriteString("- 分号注入 (`;/`, `/;//`, `;foo=bar/`)\n")
	sb.WriteString("- URL 编码混淆 (`%2e/`, `%2f`, `%25%32%66`)\n")
	sb.WriteString("- 双重编码 (`%252f`, `%252e%252e%253b/`)\n")
	sb.WriteString("- Unicode 编码 (`%ef%bc%8f`, `%c0%af`, `%u002f`)\n")
	sb.WriteString("- 后缀伪装 (`.js`, `.json`, `;.css`, `.wsdl`)\n")
	sb.WriteString("- 大小写变异（全大写、交替、首字母、末段变异）\n")
	sb.WriteString("- 查询参数污染 (`?`, `??`, `?debug=1`, `#`)\n")
	sb.WriteString("- Tab/Null 字节注入 (`%09`, `%00`, `%0d%0a`)\n")
	sb.WriteString("- `;%09..;/` 穿越模式（Spring Security/Shiro 绕过）\n")
	sb.WriteString("- CRLF 注入 (`%0d%0a`, Unicode CRLF 变体)\n")
	sb.WriteString("- 路径中间注入（midpaths: `/../`, `/.;/`, `/%00/` 等）\n")
	sb.WriteString("- 路径末尾变异（endpaths: `/.`, `/..`, `%00`, `;/` 等）\n\n")

	sb.WriteString("**Header 绕过技术覆盖：**\n\n")
	sb.WriteString("- IP 伪造头 (X-Forwarded-For, X-Real-IP 等 40+ 种 × 22 IP)\n")
	sb.WriteString("- 路径重写头 (X-Original-URL, X-Rewrite-URL, X-Override-URL, X-Accel-Redirect, X-Forwarded-Path)\n")
	sb.WriteString("- 方法覆盖头 (X-HTTP-Method-Override 等)\n")
	sb.WriteString("- HTTP 方法智能探测 (OPTIONS → Allow 头解析 → 精准测试)\n")
	sb.WriteString("- Verb-Case 切换 (gEt, GeT 等大小写变体)\n")
	sb.WriteString("- Referer 伪造、Content-Length:0 等\n")
	sb.WriteString("- Host 头注入 (localhost, 127.0.0.1, k8s 内部 Service Host)\n")
	sb.WriteString("- X-Forwarded-Proto/Port/Scheme 协议伪造\n")
	sb.WriteString("- User-Agent 伪装 (Googlebot, Bingbot 等)\n")
	sb.WriteString("- HTTP/1.0 降级模拟 (Via 头)\n")
	sb.WriteString("- X-Accel-Redirect Nginx 内部重定向绕过\n")
	sb.WriteString("- 多头组合攻击 (同时注入 8+ 个绕过头)\n")
	sb.WriteString("- Hop-by-Hop 头利用 (Connection 头剥离鉴权头)\n")
	sb.WriteString("- 自定义非标准 HTTP 方法 (FOO, JEFF, PROPFIND 等)\n")
	sb.WriteString("- Spring antMatchers 尾斜杠绕过 (`/admin` vs `/admin/`)\n")
	sb.WriteString("- Spring regexMatchers 换行注入 (`%0a`, `%0d` 绕过正则)\n")
	sb.WriteString("- Spring 后缀模式匹配 (`.action`, `.do`, `.htm`)\n\n")

	// ======== 结果统计 ========
	sb.WriteString("## 3. 结果统计\n\n")

	allData := mergeAllData(getSheet, postSheet, headerSheet)
	stats := countByClassificationPrefix(allData)

	sb.WriteString("| 判定分类 | 数量 | 风险等级 |\n")
	sb.WriteString("|---|:---:|:---:|\n")

	riskMap := map[string]string{
		"可能绕过(高)":  "**严重**",
		"可能绕过(中)":  "**高**",
		"可能绕过(低)":  "中",
		"长度差异大(高)": "**高**",
		"长度差异大(中)": "中",
		"长度差异小":    "低",
		"重定向(需关注)": "中",
		"重定向":      "信息",
		"拒绝访问(403)": "信息",
		"拒绝访问(401)": "信息",
	}
	order := []string{
		"可能绕过(高)", "可能绕过(中)", "可能绕过(低)",
		"长度差异大(高)", "长度差异大(中)",
		"重定向(需关注)", "长度差异小", "重定向",
		"拒绝访问(403)", "拒绝访问(401)",
	}

	for _, cls := range order {
		if cnt, ok := stats[cls]; ok {
			risk := riskMap[cls]
			if risk == "" {
				risk = "信息"
			}
			sb.WriteString(fmt.Sprintf("| %s | %d | %s |\n", cls, cnt, risk))
			delete(stats, cls)
		}
	}
	for cls, cnt := range stats {
		sb.WriteString(fmt.Sprintf("| %s | %d | 信息 |\n", cls, cnt))
	}
	sb.WriteString("\n")

	// ======== 可能绕过详情 ========
	bypasses := filterByClassificationPrefix(allData, "可能绕过")
	largeDiff := filterByClassificationPrefix(allData, "长度差异大")
	needAttention := filterByClassificationPrefix(allData, "重定向(需关注")
	suspects := append(bypasses, largeDiff...)
	suspects = append(suspects, needAttention...)

	if len(suspects) > 0 {
		sb.WriteString("## 4. 疑似绕过成功 — 详细分析\n\n")
		sb.WriteString("> 以下结果按置信度排序，置信度越高越需要优先验证。\n")
		sb.WriteString("> 需人工验证响应内容是否确实返回了受保护的数据。\n\n")

		for i, item := range suspects {
			confidence := ExtractConfidence(item.classification)
			confidenceTag := ""
			if confidence != "" {
				confidenceTag = fmt.Sprintf(" [置信度: %s]", confidence)
			}

			sb.WriteString(fmt.Sprintf("### 4.%d %s%s\n\n", i+1, item.classification, confidenceTag))
			sb.WriteString("```\n")
			sb.WriteString(fmt.Sprintf("请求方法:   %s\n", item.method))
			sb.WriteString(fmt.Sprintf("完整 URL:   %s\n", item.url))
			sb.WriteString(fmt.Sprintf("响应状态码: %s\n", item.statusCode))
			sb.WriteString(fmt.Sprintf("响应长度:   %s\n", item.length))
			sb.WriteString("```\n\n")

			sb.WriteString("**绕过依据：**\n\n")
			sb.WriteString(fmt.Sprintf("- 鉴权接口原始响应: `code=%d, len=%d`\n", meta.OrigCode, meta.OrigLen))
			if meta.NoAuthCode > 0 {
				sb.WriteString(fmt.Sprintf("- 无鉴权接口基准响应: `code=%d, len=%d`\n", meta.NoAuthCode, meta.NoAuthLen))
			}
			sb.WriteString(fmt.Sprintf("- 当前 Payload 响应: `code=%s, len=%s`\n", item.statusCode, item.length))

			baseLabel := ExtractBaseLabel(item.classification)
			switch {
			case baseLabel == "可能绕过" && confidence == "高":
				sb.WriteString("- 状态码从鉴权拦截变为 200，且响应长度与无鉴权接口高度相似（>90%），无登录页面特征\n")
				sb.WriteString("- **高概率绕过成功，优先验证**\n")
			case baseLabel == "可能绕过" && confidence == "中":
				sb.WriteString("- 状态码从鉴权拦截变为 200，响应与无鉴权接口存在一定相似性\n")
				sb.WriteString("- 建议人工验证响应体内容\n")
			case baseLabel == "可能绕过" && confidence == "低":
				sb.WriteString("- 状态码变为 200，但响应体中检测到登录/错误页面关键词\n")
				sb.WriteString("- 可能是 WAF/中间件返回的自定义 200 错误页，误报概率较高\n")
			case baseLabel == "长度差异大":
				sb.WriteString("- 响应长度与鉴权接口存在显著差异（超过比例阈值）\n")
				if confidence == "高" {
					sb.WriteString("- 响应长度更接近无鉴权接口，可能返回了真实业务数据\n")
				}
			case baseLabel == "重定向(需关注)":
				sb.WriteString("- 重定向目标不是登录相关路径，可能是绕过后的业务页面跳转\n")
			}

			sb.WriteString("\n**复现命令：**\n\n")
			sb.WriteString("```bash\n")
			if item.curlCmd != "" {
				sb.WriteString(item.curlCmd + "\n")
			} else if item.method == "GET" || item.method == "" || !strings.HasPrefix(item.method, "POST") {
				sb.WriteString(fmt.Sprintf("curl -k -v \"%s\"\n", item.url))
			} else {
				sb.WriteString(fmt.Sprintf("curl -k -v -X %s \"%s\"\n", item.method, item.url))
			}
			sb.WriteString("```\n\n")
			sb.WriteString("---\n\n")
		}
	} else {
		sb.WriteString("## 4. 疑似绕过成功\n\n")
		sb.WriteString("本次测试未发现明确的鉴权绕过迹象。所有 Payload 的响应均被正确拦截或与原始响应一致。\n\n")
	}

	// ======== 测试结论 ========
	sb.WriteString("## 5. 测试结论\n\n")

	highBypasses := filterByClassificationSuffix(bypasses, "(高)")
	medBypasses := filterByClassificationSuffix(bypasses, "(中)")

	if len(highBypasses) > 0 {
		sb.WriteString(fmt.Sprintf("**发现 %d 个高置信度绕过结果**，强烈建议立即验证：\n\n", len(highBypasses)))
		sb.WriteString("1. 使用 curl 或 Burp Suite 逐一验证响应内容\n")
		sb.WriteString("2. 确认响应体是否包含受保护的业务数据\n")
		sb.WriteString("3. 如确认绕过，排查鉴权中间件对路径规范化的处理逻辑\n")
		sb.WriteString("4. 重点关注 Spring Security 的 `AntPathMatcher` / `PathPattern` 配置差异\n")
		sb.WriteString("5. 检查 Nginx/Apache 反向代理的路径规范化配置是否与后端一致\n")
	} else if len(medBypasses) > 0 || len(largeDiff) > 0 {
		total := len(medBypasses) + len(largeDiff)
		sb.WriteString(fmt.Sprintf("未发现高置信度绕过，但存在 %d 个中等置信度异常结果，建议人工验证。\n", total))
	} else if len(needAttention) > 0 {
		sb.WriteString(fmt.Sprintf("存在 %d 个非登录重定向结果，建议检查重定向目标是否为业务页面。\n", len(needAttention)))
	} else {
		sb.WriteString("本次测试未发现鉴权绕过漏洞。目标接口的鉴权机制在当前测试覆盖范围内表现正常。\n")
	}
	sb.WriteString("\n---\n\n")
	sb.WriteString("*本报告由 NoAuth_V2 自动生成，结果仅供参考，请结合人工验证确认。*\n")

	// 写入文件
	if err := os.WriteFile(filePath, []byte(sb.String()), 0644); err != nil {
		fmt.Printf(Red("[-] 保存报告失败: %s\n"), err)
		return
	}

	fmt.Printf(Green("[+] 测试报告已生成: %s\n"), filePath)
}

// suspectItem 疑似绕过条目
type suspectItem struct {
	url            string
	method         string
	length         string
	statusCode     string
	classification string
	curlCmd        string // 复现命令
}

// mergeAllData 合并所有 Sheet 数据，并附加来源标记
func mergeAllData(sheets ...SheetData) []suspectItem {
	var items []suspectItem
	for _, sheet := range sheets {
		for _, row := range sheet.Data {
			item := suspectItem{}
			if len(row) > 0 {
				item.url = row[0]
			}
			// 根据不同 Sheet 的列结构解析
			switch sheet.Name {
			case "GET 测试":
				// 列: URL, 响应长度, 状态码, 判定, 复现命令
				if len(row) > 1 { item.length = row[1] }
				if len(row) > 2 { item.statusCode = row[2] }
				if len(row) > 3 { item.classification = row[3] }
				if len(row) > 4 { item.curlCmd = row[4] }
				item.method = "GET"
			case "POST 测试":
				// 列: URL, 响应长度, 状态码, 请求类型, 判定, 复现命令
				if len(row) > 1 { item.length = row[1] }
				if len(row) > 2 { item.statusCode = row[2] }
				if len(row) > 3 { item.method = row[3] }
				if len(row) > 4 { item.classification = row[4] }
				if len(row) > 5 { item.curlCmd = row[5] }
			case "Header/Method 测试":
				// 列: 绕过技术, URL, 响应长度, 状态码, 判定, 复现命令
				if len(row) > 0 { item.method = row[0] }
				if len(row) > 1 { item.url = row[1] }
				if len(row) > 2 { item.length = row[2] }
				if len(row) > 3 { item.statusCode = row[3] }
				if len(row) > 4 { item.classification = row[4] }
				if len(row) > 5 { item.curlCmd = row[5] }
			}
			items = append(items, item)
		}
	}
	return items
}

// countByClassificationPrefix 按完整分类标签统计（包含置信度）
func countByClassificationPrefix(items []suspectItem) map[string]int {
	stats := make(map[string]int)
	for _, item := range items {
		if item.classification != "" {
			stats[item.classification]++
		}
	}
	return stats
}

// filterByClassificationPrefix 按前缀筛选判定类型
func filterByClassificationPrefix(items []suspectItem, prefix string) []suspectItem {
	var result []suspectItem
	for _, item := range items {
		if strings.HasPrefix(item.classification, prefix) {
			result = append(result, item)
		}
	}
	return result
}

// filterByClassificationSuffix 按后缀筛选（用于区分置信度）
func filterByClassificationSuffix(items []suspectItem, suffix string) []suspectItem {
	var result []suspectItem
	for _, item := range items {
		if strings.HasSuffix(item.classification, suffix) {
			result = append(result, item)
		}
	}
	return result
}

// countTotal 估算总 payload 数（用于报告展示）
func countTotal(sheet SheetData) int {
	if sheet.TotalPayloads > 0 {
		return sheet.TotalPayloads
	}
	return len(sheet.Data)
}
