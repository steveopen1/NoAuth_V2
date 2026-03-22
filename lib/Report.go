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
	TargetURL string
	NoAuth    string
	Auth      string
	Threads   int
	Timeout   int
	Proxy     string
	Debug     int
	OrigCode  int
	OrigLen   int
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
	sb.WriteString(fmt.Sprintf("| 原始响应 | code=%d, len=%d |\n", meta.OrigCode, meta.OrigLen))
	sb.WriteString(fmt.Sprintf("| 并发线程 | %d |\n", meta.Threads))
	sb.WriteString(fmt.Sprintf("| 超时时间 | %d 秒 |\n", meta.Timeout))
	if meta.Proxy != "" {
		sb.WriteString(fmt.Sprintf("| 代理 | `%s` |\n", meta.Proxy))
	}
	sb.WriteString(fmt.Sprintf("| 测试时间 | %s |\n", time.Now().Format("2006-01-02 15:04:05")))
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
	sb.WriteString("- 大小写变异、双斜线、空格编码、反斜杠\n")
	sb.WriteString("- 查询参数污染 (`?`, `??`, `?debug=1`, `#`)\n")
	sb.WriteString("- Tab/Null 字节注入 (`%09`, `%00`, `%0d%0a`)\n\n")

	sb.WriteString("**Header 绕过技术覆盖：**\n\n")
	sb.WriteString("- IP 伪造头 (X-Forwarded-For, X-Real-IP 等 22 种 × 10 IP)\n")
	sb.WriteString("- 路径重写头 (X-Original-URL, X-Rewrite-URL, X-Override-URL)\n")
	sb.WriteString("- 方法覆盖头 (X-HTTP-Method-Override 等)\n")
	sb.WriteString("- HTTP 方法智能探测 (OPTIONS → Allow 头解析 → 精准测试)\n")
	sb.WriteString("- Referer 伪造、Content-Length:0 等\n\n")

	// ======== 结果统计 ========
	sb.WriteString("## 3. 结果统计\n\n")

	allData := mergeAllData(getSheet, postSheet, headerSheet)
	stats := countByClassification(allData)

	sb.WriteString("| 判定分类 | 数量 | 风险等级 |\n")
	sb.WriteString("|---|:---:|:---:|\n")

	riskMap := map[string]string{
		"可能绕过": "**高**",
		"长度差异大": "**中**",
		"长度差异小": "低",
		"重定向":   "信息",
		"拒绝访问":  "信息",
	}
	order := []string{"可能绕过", "长度差异大", "长度差异小", "重定向", "拒绝访问"}

	for _, cls := range order {
		if cnt, ok := stats[cls]; ok {
			risk := riskMap[cls]
			sb.WriteString(fmt.Sprintf("| %s | %d | %s |\n", cls, cnt, risk))
			delete(stats, cls)
		}
	}
	for cls, cnt := range stats {
		sb.WriteString(fmt.Sprintf("| %s | %d | 信息 |\n", cls, cnt))
	}
	sb.WriteString("\n")

	// ======== 可能绕过详情 ========
	bypasses := filterByClassification(allData, "可能绕过")
	largeDiff := filterByClassification(allData, "长度差异大")
	suspects := append(bypasses, largeDiff...)

	if len(suspects) > 0 {
		sb.WriteString("## 4. 疑似绕过成功 — 详细分析\n\n")
		sb.WriteString("> 以下结果的响应特征与原始鉴权接口存在显著差异，可能表示鉴权被绕过。\n")
		sb.WriteString("> 需人工验证响应内容是否确实返回了受保护的数据。\n\n")

		for i, item := range suspects {
			sb.WriteString(fmt.Sprintf("### 4.%d %s\n\n", i+1, item.classification))
			sb.WriteString("```\n")
			sb.WriteString(fmt.Sprintf("请求方法:   %s\n", item.method))
			sb.WriteString(fmt.Sprintf("完整 URL:   %s\n", item.url))
			sb.WriteString(fmt.Sprintf("响应状态码: %s\n", item.statusCode))
			sb.WriteString(fmt.Sprintf("响应长度:   %s\n", item.length))
			sb.WriteString("```\n\n")

			sb.WriteString("**绕过依据：**\n\n")
			sb.WriteString(fmt.Sprintf("- 原始鉴权接口响应: `code=%d, len=%d`\n", meta.OrigCode, meta.OrigLen))
			sb.WriteString(fmt.Sprintf("- 当前 Payload 响应: `code=%s, len=%s`\n", item.statusCode, item.length))

			if item.classification == "可能绕过" {
				sb.WriteString(fmt.Sprintf("- 原始状态码为 `%d`（鉴权拦截），当前返回 `%s`（正常响应），", meta.OrigCode, item.statusCode))
				sb.WriteString("表明请求可能绕过了鉴权中间件到达了业务逻辑层\n")
			} else {
				sb.WriteString("- 响应长度与原始鉴权接口差异超过 100 字节，可能包含了不同的页面内容\n")
			}

			sb.WriteString("\n**预期响应特征（供人工比对）：**\n\n")
			sb.WriteString("```http\n")
			sb.WriteString(fmt.Sprintf("HTTP/1.1 %s\n", item.statusCode))
			sb.WriteString(fmt.Sprintf("Content-Length: %s\n", item.length))
			sb.WriteString("\n")
			sb.WriteString("// 如果响应体中包含业务数据（如用户信息、管理功能页面），则确认绕过成功\n")
			sb.WriteString("// 如果响应体为通用错误页或空白页，则为误报\n")
			sb.WriteString("```\n\n")

			sb.WriteString("**复现命令：**\n\n")
			sb.WriteString("```bash\n")
			if item.method == "GET" || item.method == "" {
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
	if len(bypasses) > 0 {
		sb.WriteString(fmt.Sprintf("**发现 %d 个高风险疑似绕过结果**，建议：\n\n", len(bypasses)))
		sb.WriteString("1. 使用 curl 或 Burp Suite 逐一验证上述 URL 的响应内容\n")
		sb.WriteString("2. 确认响应体是否包含受保护的业务数据\n")
		sb.WriteString("3. 如确认绕过，排查鉴权中间件对路径规范化的处理逻辑\n")
		sb.WriteString("4. 重点关注 Spring Security 的 `AntPathMatcher` / `PathPattern` 配置差异\n")
	} else if len(largeDiff) > 0 {
		sb.WriteString(fmt.Sprintf("未发现确定性绕过，但存在 %d 个响应长度差异较大的结果，建议人工验证。\n", len(largeDiff)))
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
				if len(row) > 1 { item.length = row[1] }
				if len(row) > 2 { item.statusCode = row[2] }
				if len(row) > 3 { item.classification = row[3] }
				item.method = "GET"
			case "POST 测试":
				if len(row) > 1 { item.length = row[1] }
				if len(row) > 2 { item.statusCode = row[2] }
				if len(row) > 3 { item.method = row[3] } // POST-Form / POST-Json
				if len(row) > 4 { item.classification = row[4] }
			case "Header/Method 测试":
				// 列: 绕过技术, URL, 响应长度, 状态码, 判定
				if len(row) > 0 { item.method = row[0] } // 绕过技术描述
				if len(row) > 1 { item.url = row[1] }
				if len(row) > 2 { item.length = row[2] }
				if len(row) > 3 { item.statusCode = row[3] }
				if len(row) > 4 { item.classification = row[4] }
			}
			items = append(items, item)
		}
	}
	return items
}

// countByClassification 按判定分类统计
func countByClassification(items []suspectItem) map[string]int {
	stats := make(map[string]int)
	for _, item := range items {
		if item.classification != "" {
			stats[item.classification]++
		}
	}
	return stats
}

// filterByClassification 筛选特定判定类型
func filterByClassification(items []suspectItem, classification string) []suspectItem {
	var result []suspectItem
	for _, item := range items {
		if item.classification == classification {
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
