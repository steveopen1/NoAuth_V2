package poc

// QueryFragment 生成查询参数和片段污染的 payload
func QueryFragment(auth string) []string {
	suffixes := []string{
		"?",
		"??",
		"???",
		"?anything=value",
		"?testparam",
		"?debug=1",
		"?debug=true",
		"?WSDL",
		"?wsdl",
		"?&",
		"#",
		"#/",
		"#test",
		"#/.//",
		"&",
		"&debug=1",
	}

	var results []string
	for _, s := range suffixes {
		results = append(results, auth+s)
	}
	return results
}
