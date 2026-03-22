package lib

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type Variant struct {
	Name        string
	Type        string
	MutatedURL  string
	MutatedBody string
}

var (
	JSONValueRegex    = regexp.MustCompile(`"([^"]+)":\s*(-?\d+)`)
	JSONStringRegex   = regexp.MustCompile(`"([^"]+)":\s*"([^"]*)"`)
	JSONBoolNullRegex = regexp.MustCompile(`"([^"]+)":\s*(true|false|null)`)
	FormParamRegex    = regexp.MustCompile(`([^=]+)=([^&]*)`)
)

func GenerateAllVariants(req *ParsedRequest) []Variant {
	var variants []Variant

	parsedURL, err := url.Parse(req.URL)
	if err == nil {
		variants = append(variants, generateURLPathSuffixes(parsedURL)...)
		variants = append(variants, generateURLPathFuzz(parsedURL)...)
	}

	variants = append(variants, generateURLParamVariants(req)...)
	variants = append(variants, generateJSONVariants(req)...)
	variants = append(variants, generateFormVariants(req)...)

	return variants
}

func generateURLPathFuzz(parsed *url.URL) []Variant {
	var variants []Variant

	path := parsed.Path
	if path == "" || path == "/" {
		return variants
	}

	basePath := path
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash > 0 {
		basePath = path[:lastSlash]
	}

	midPaths := []string{
		";", ";.", "..;", "../..", "../../", "../../..",
		"./", "./..", "/.", "/..", "//", "////",
		"%20", "%09", "%0a", "%0d", "%00", "%ff",
		"%2e", "%2e%2e", "%2f", "%2f%2f",
		"~", "`", "\\", "\n", "\r",
		";vulnerable", ";x", ";test",
		"/.;/", "/..;/", "/../;", "/..%00",
		"/%2e/", "/%2e%2e/", "/%2f",
		"/randomstring", "/.randomstring",
		"/.././../", "/;/..",
	}

	for _, mid := range midPaths {
		variants = append(variants, Variant{
			Name:       fmt.Sprintf("PathFuzz[mid:%s][%s]", mid, path),
			Type:       "url",
			MutatedURL: fmt.Sprintf("%s://%s%s/%s", parsed.Scheme, parsed.Host, basePath, mid),
		})
	}

	endPaths := []string{
		"", "/*", "/.", "/..", "/.../", "/;",
		"/..;", "/;", "/.html", "/.json", "/.xml", "/.txt",
		"/%00", "/%20", "/%09", "/null", "/undefined",
		"/test", "/debug", "/debug=1", "/?",
		"/#", "/#/", "/.../", "/..;",
		"/WSDL", "/wsdl", "/?debug=1", "/?test",
		"/~", "/`", "/\\",
	}

	for _, end := range endPaths {
		variants = append(variants, Variant{
			Name:       fmt.Sprintf("PathFuzz[end:%s][%s]", end, path),
			Type:       "url",
			MutatedURL: fmt.Sprintf("%s://%s%s%s", parsed.Scheme, parsed.Host, path, end),
		})
	}

	return variants
}

func generateURLParamVariants(req *ParsedRequest) []Variant {
	var variants []Variant

	if !strings.Contains(req.URL, "?") {
		return variants
	}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return variants
	}

	queryValues, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		return variants
	}

	if len(queryValues) == 0 {
		return variants
	}

	paramNames := make([]string, 0, len(queryValues))
	for name := range queryValues {
		paramNames = append(paramNames, name)
	}

	for i, name := range paramNames {
		values := queryValues[name]
		if len(values) == 0 {
			continue
		}

		value := values[0]

		if name == strings.ToLower(name) && i+1 < len(paramNames) {
			nextName := paramNames[i+1]
			nextValue := queryValues[nextName][0]
			variants = append(variants, Variant{
				Name:       fmt.Sprintf("URLParamPollution[%s=%s&%s=%s]", name, value, nextName, nextValue),
				Type:       "url",
				MutatedURL: buildPollutedURL(parsedURL, name, value, nextName, nextValue),
			})
		}

		if strings.ToLower(name) != name {
			lowerName := strings.ToLower(name)
			if _, exists := queryValues[lowerName]; exists {
				variants = append(variants, Variant{
					Name:       fmt.Sprintf("URLParamPollution[%s=%s&%s=%s]", lowerName, queryValues[lowerName][0], name, value),
					Type:       "url",
					MutatedURL: buildPollutedURL(parsedURL, lowerName, queryValues[lowerName][0], name, value),
				})
			}
		}

		variants = append(variants, Variant{
			Name:       fmt.Sprintf("ParamOrder[%s=%s&%s=%s]", name, value, name, value),
			Type:       "url",
			MutatedURL: buildOrderedURL(parsedURL, name, value),
		})
	}

	encodedAmp := strings.Replace(req.URL, "&", "%26", 1)
	if encodedAmp != req.URL {
		variants = append(variants, Variant{
			Name:       "URLEncodeAmp[& -> %26]",
			Type:       "url",
			MutatedURL: encodedAmp,
		})
	}

	return variants
}

func generateURLPathSuffixes(parsed *url.URL) []Variant {
	var variants []Variant

	path := parsed.Path
	if path == "" || path == "/" {
		return variants
	}

	suffixes := []string{".json", ".xml", ".html", ".txt", ".yml", ".yaml"}
	for _, suffix := range suffixes {
		variants = append(variants, Variant{
			Name:       fmt.Sprintf("PathSuffix[%s -> %s%s]", path, path, suffix),
			Type:       "url",
			MutatedURL: fmt.Sprintf("%s://%s%s%s", parsed.Scheme, parsed.Host, path, suffix),
		})
	}

	doubleSlash := strings.Replace(path, "//", "/", 1)
	if doubleSlash != path {
		variants = append(variants, Variant{
			Name:       fmt.Sprintf("DoubleSlash[%s -> %s]", path, doubleSlash),
			Type:       "url",
			MutatedURL: fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, doubleSlash),
		})
	}

	if !strings.HasSuffix(path, "/") {
		variants = append(variants, Variant{
			Name:       fmt.Sprintf("TrailSlash[%s -> %s/]", path, path),
			Type:       "url",
			MutatedURL: fmt.Sprintf("%s://%s%s/", parsed.Scheme, parsed.Host, path),
		})
	} else {
		noTrailSlash := strings.TrimSuffix(path, "/")
		variants = append(variants, Variant{
			Name:       fmt.Sprintf("NoTrailSlash[%s -> %s]", path, noTrailSlash),
			Type:       "url",
			MutatedURL: fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, noTrailSlash),
		})
	}

	return variants
}

func buildPollutedURL(parsed *url.URL, name1, val1, name2, val2 string) string {
	q := parsed.Query()
	delete(q, name1)
	delete(q, name2)

	newQuery := fmt.Sprintf("%s=%s&%s=%s", name1, url.QueryEscape(val1), name2, url.QueryEscape(val2))
	if q.Encode() != "" {
		newQuery = newQuery + "&" + q.Encode()
	}

	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, newQuery)
}

func buildOrderedURL(parsed *url.URL, name, value string) string {
	q := parsed.Query()
	vals := q[name]
	if len(vals) > 0 {
		q.Del(name)
		for _, v := range vals[1:] {
			q.Add(name, v)
		}
		q.Add(name, value)
	}
	return fmt.Sprintf("%s://%s%s?%s", parsed.Scheme, parsed.Host, parsed.Path, q.Encode())
}

func generateJSONVariants(req *ParsedRequest) []Variant {
	var variants []Variant

	if !isJSONFormat(req.Body) {
		return variants
	}

	jsonBody := req.Body

	variants = append(variants, generateJSONArrayWrap(jsonBody)...)
	variants = append(variants, generateJSONNest(jsonBody)...)
	variants = append(variants, generateJSONWildcard(jsonBody)...)
	variants = append(variants, generateJSONUnicode(jsonBody)...)

	return variants
}

func generateJSONUnicode(body string) []Variant {
	var variants []Variant

	matches := JSONStringRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		key := match[1]
		value := match[2]

		for _, uStr := range []string{"\u200b", "\u3000", "\u00a0"} {
			oldPattern := fmt.Sprintf(`"%s":"%s"`, key, value)
			newPattern := fmt.Sprintf(`"%s%s":"%s"`, key, uStr, value)
			if strings.Contains(body, oldPattern) {
				mutated := strings.Replace(body, oldPattern, newPattern, 1)
				variants = append(variants, Variant{
					Name:        fmt.Sprintf("JSONUnicode[%s: key injection %x]", key, []byte(uStr)),
					Type:        "json",
					MutatedBody: mutated,
				})
			}
		}
	}

	return variants
}

func generateJSONArrayWrap(body string) []Variant {
	var variants []Variant

	matches := JSONValueRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		key := match[1]
		value := match[2]

		oldPattern := fmt.Sprintf(`"%s":%s`, key, value)
		newPattern := fmt.Sprintf(`"%s":[%s]`, key, value)

		if strings.Contains(body, oldPattern) {
			mutated := strings.Replace(body, oldPattern, newPattern, 1)
			variants = append(variants, Variant{
				Name:        fmt.Sprintf("ArrayWrap[%s:%s -> %s]", key, value, newPattern),
				Type:        "json",
				MutatedBody: mutated,
			})
		}
	}

	return variants
}

func generateJSONNest(body string) []Variant {
	var variants []Variant

	matches := JSONValueRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		key := match[1]
		value := match[2]

		oldPattern := fmt.Sprintf(`"%s":%s`, key, value)
		newPattern := fmt.Sprintf(`"%s":{"%s":%s}`, key, key, value)

		if strings.Contains(body, oldPattern) {
			mutated := strings.Replace(body, oldPattern, newPattern, 1)
			variants = append(variants, Variant{
				Name:        fmt.Sprintf("JSONNest[%s:%s -> nested]", key, value),
				Type:        "json",
				MutatedBody: mutated,
			})
		}

		deepPattern := fmt.Sprintf(`"%s":{"%s":{"%s":%s}}`, key, key, key, value)
		if strings.Contains(body, oldPattern) {
			mutatedDeep := strings.Replace(body, oldPattern, deepPattern, 1)
			variants = append(variants, Variant{
				Name:        fmt.Sprintf("JSONDeepNest[%s:%s -> deep nested]", key, value),
				Type:        "json",
				MutatedBody: mutatedDeep,
			})
		}
	}

	stringMatches := JSONStringRegex.FindAllStringSubmatch(body, -1)
	for _, stringMatch := range stringMatches {
		if len(stringMatch) < 3 {
			continue
		}
		key := stringMatch[1]
		value := stringMatch[2]

		oldPattern := fmt.Sprintf(`"%s":"%s"`, key, value)
		newPattern := fmt.Sprintf(`"%s":{"%s":"%s"}`, key, key, value)

		if strings.Contains(body, oldPattern) {
			mutated := strings.Replace(body, oldPattern, newPattern, 1)
			variants = append(variants, Variant{
				Name:        fmt.Sprintf("JSONNest[%s:\"%s\" -> nested]", key, value),
				Type:        "json",
				MutatedBody: mutated,
			})
		}

		deepPattern := fmt.Sprintf(`"%s":{"%s":{"%s":"%s"}}`, key, key, key, value)
		if strings.Contains(body, oldPattern) {
			mutatedDeep := strings.Replace(body, oldPattern, deepPattern, 1)
			variants = append(variants, Variant{
				Name:        fmt.Sprintf("JSONDeepNest[%s:\"%s\" -> deep nested]", key, value),
				Type:        "json",
				MutatedBody: mutatedDeep,
			})
		}
	}

	return variants
}

func generateJSONWildcard(body string) []Variant {
	var variants []Variant

	matches := JSONStringRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		key := match[1]
		value := match[2]

		if value == "" || value == "*" || value == "%" || value == "?" || value == "null" {
			continue
		}

		wildcards := []string{"*", "%", "?", "-1", "null", "0", "1"}
		for _, wc := range wildcards {
			oldPattern := fmt.Sprintf(`"%s":"%s"`, key, value)
			newPattern := fmt.Sprintf(`"%s":"%s"`, key, wc)

			if strings.Contains(body, oldPattern) {
				mutated := strings.Replace(body, oldPattern, newPattern, 1)
				variants = append(variants, Variant{
					Name:        fmt.Sprintf("Wildcard[%s:\"%s\" -> \"%s\"]", key, value, wc),
					Type:        "json",
					MutatedBody: mutated,
				})
			}
		}
	}

	boolMatches := JSONBoolNullRegex.FindAllStringSubmatch(body, -1)
	for _, match := range boolMatches {
		if len(match) < 3 {
			continue
		}
		key := match[1]
		value := match[2]

		replacements := []string{"1", "0", "-1"}
		for _, r := range replacements {
			oldPattern := fmt.Sprintf(`"%s":%s`, key, value)
			newPattern := fmt.Sprintf(`"%s":%s`, key, r)

			if strings.Contains(body, oldPattern) {
				mutated := strings.Replace(body, oldPattern, newPattern, 1)
				variants = append(variants, Variant{
					Name:        fmt.Sprintf("Wildcard[%s:%s -> %s]", key, value, r),
					Type:        "json",
					MutatedBody: mutated,
				})
			}
		}
	}

	return variants
}

func generateFormVariants(req *ParsedRequest) []Variant {
	var variants []Variant

	if !isFormFormat(req.Body) {
		return variants
	}

	formBody := req.Body

	matches := FormParamRegex.FindAllStringSubmatch(formBody, -1)
	seenParams := make(map[string]bool)

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		param := match[1]
		value := match[2]

		if seenParams[param] {
			continue
		}
		seenParams[param] = true

		variants = append(variants, Variant{
			Name:        fmt.Sprintf("FormArray[%s=%s -> %s[]=%s]", param, value, param, value),
			Type:        "form",
			MutatedBody: strings.Replace(formBody, fmt.Sprintf("%s=%s", param, value), fmt.Sprintf("%s[]=%s", param, value), 1),
		})

		variants = append(variants, Variant{
			Name:        fmt.Sprintf("FormPollution[%s=%s -> %s=%s&%s=%s]", param, value, param, value, param, value),
			Type:        "form",
			MutatedBody: formBody + "&" + param + "=" + value,
		})
	}

	return variants
}

func BuildMutatedRequest(req *ParsedRequest, variant *Variant) (string, map[string]string, string) {
	headers := make(map[string]string)
	for k, v := range req.Headers {
		headers[k] = v
	}

	switch variant.Type {
	case "url":
		return variant.MutatedURL, headers, req.Body
	case "json":
		if variant.MutatedBody != "" {
			headers["Content-Type"] = "application/json"
		}
		return req.URL, headers, variant.MutatedBody
	case "form":
		if variant.MutatedBody != "" {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}
		return req.URL, headers, variant.MutatedBody
	default:
		return req.URL, headers, req.Body
	}
}
