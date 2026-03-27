package detect

import (
	"fmt"
	"strings"
)

type ProtocolBypass struct {
	Name        string
	Description string
	Header      string
	Value       string
}

var ProtocolBypasses = []ProtocolBypass{
	{Name: "HTTP10", Description: "HTTP/1.0 protocol downgrade", Header: "Via", Value: "1.0"},
	{Name: "HTTP10Alias", Description: "HTTP/1.0 via alias", Header: "Via", Value: "1.0 proxy"},
	{Name: "HTTP11", Description: "Explicit HTTP/1.1", Header: "Via", Value: "1.1"},
	{Name: "Forwarded", Description: "Forwarded header", Header: "Forwarded", Value: "for=127.0.0.1"},
	{Name: "XForwardedProto", Description: "X-Forwarded-Proto header", Header: "X-Forwarded-Proto", Value: "http"},
	{Name: "XForwardedSsl", Description: "X-Forwarded-SSL on", Header: "X-Forwarded-SSL", Value: "on"},
	{Name: "XForwardedSslColon", Description: "X-Forwarded-SSL: ssl", Header: "X-Forwarded-SSL", Value: "ssl"},
	{Name: "FrontEndHttps", Description: "Front-End-Https on", Header: "Front-End-Https", Value: "on"},
	{Name: "Profile", Description: "Profile header", Header: "Profile", Value: "http://localhost"},
	{Name: "Protocol", Description: "Protocol header", Header: "Protocol", Value: "http/1.0"},
}

func GetProtocolBypasses() []ProtocolBypass {
	return ProtocolBypasses
}

func GetHTTP2Bypasses() []ProtocolBypass {
	return []ProtocolBypass{
		{Name: "HTTP2Setting", Description: "HTTP/2 settings override", Header: "HTTP2-Settings", Value: "AAM="},
		{Name: "HTTP2Upgrade", Description: "HTTP/2 upgrade request", Header: "Upgrade", Value: "h2c"},
		{Name: "HTTP2PriorKnowledge", Description: "HTTP/2 prior knowledge", Header: "", Value: ""},
	}
}

func BuildProtocolHeader(header string, value string) map[string]string {
	headers := make(map[string]string)
	if header != "" && value != "" {
		headers[header] = value
	}
	return headers
}

type MethodVariant struct {
	Method string
	Name   string
}

var MethodVariants = []MethodVariant{
	{"GET", "Standard GET"},
	{"POST", "Standard POST"},
	{"PUT", "Standard PUT"},
	{"DELETE", "Standard DELETE"},
	{"PATCH", "Standard PATCH"},
	{"HEAD", "Standard HEAD"},
	{"OPTIONS", "Standard OPTIONS"},
	{"TRACE", "Standard TRACE"},
	{"CONNECT", "Standard CONNECT"},
	{"PROPFIND", "WebDAV PROPFIND"},
	{"PROPPATCH", "WebDAV PROPPATCH"},
	{"MKCOL", "WebDAV MKCOL"},
	{"COPY", "WebDAV COPY"},
	{"MOVE", "WebDAV MOVE"},
	{"LOCK", "WebDAV LOCK"},
	{"UNLOCK", "WebDAV UNLOCK"},
	{"VERSION-CONTROL", "WebDAV VERSION-CONTROL"},
	{"REPORT", "WebDAV REPORT"},
	{"CHECKOUT", "WebDAV CHECKOUT"},
	{"CHECKIN", "WebDAV CHECKIN"},
	{"UNCHECKOUT", "WebDAV UNCHECKOUT"},
	{"MKWORKSPACE", "WebDAV MKWORKSPACE"},
	{"UPDATE", "WebDAV UPDATE"},
	{"LABEL", "WebDAV LABEL"},
	{"MERGE", "WebDAV MERGE"},
	{"BASELINE-CONTROL", "WebDAV BASELINE-CONTROL"},
	{"MKACTIVITY", "WebDAV MKACTIVITY"},
	{"ACS", "WebDAV ACS"},
	{"PATCH", "ASF PATCH"},
	{"FOO", "Custom FOO"},
	{"BAR", "Custom BAR"},
	{"JEFF", "Custom JEFF"},
	{"TEST", "Custom TEST"},
	{"NULL", "NULL byte in method"},
}

func GetMethodVariants() []MethodVariant {
	return MethodVariants
}

func IsCustomMethod(method string) bool {
	customMethods := map[string]bool{
		"FOO": true, "BAR": true, "JEFF": true, "TEST": true,
		"NULL": true, "PURGE": true, "REINDEX": true,
		"LINK": true, "UNLINK": true, "BIND": true, "UNBIND": true,
	}
	return customMethods[strings.ToUpper(method)]
}

func GetNonStandardMethods() []MethodVariant {
	var nonStandard []MethodVariant
	for _, m := range MethodVariants {
		switch m.Method {
		case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT":
			continue
		default:
			nonStandard = append(nonStandard, m)
		}
	}
	return nonStandard
}

type HeaderChain struct {
	Name    string
	Headers map[string]string
}

func GetHeaderChains() []HeaderChain {
	return []HeaderChain{
		{
			Name: "Full Forwarded Chain",
			Headers: map[string]string{
				"X-Forwarded-For":   "127.0.0.1",
				"X-Forwarded-Host":  "localhost",
				"X-Forwarded-Proto": "http",
				"Forwarded":         "for=127.0.0.1;by=127.0.0.1;proto=http",
			},
		},
		{
			Name: "Multiple X-Forwarded",
			Headers: map[string]string{
				"X-Forwarded-For":   "127.0.0.1, 127.0.0.2, 127.0.0.3",
				"X-Forwarded-Host":  "localhost, evil.com",
				"X-Forwarded-Proto": "http, https, http",
			},
		},
		{
			Name: "Real IP Chain",
			Headers: map[string]string{
				"X-Real-IP":        "127.0.0.1",
				"X-Originating-IP": "127.0.0.1",
				"X-Remote-IP":      "127.0.0.1",
				"X-Remote-Addr":    "127.0.0.1",
			},
		},
		{
			Name: "AWS IP Chain",
			Headers: map[string]string{
				"X-Forwarded-For":  "127.0.0.1, 192.168.1.1",
				"CF-Connecting-IP": "127.0.0.1",
				"True-Client-IP":   "127.0.0.1",
				"X-Cluster-IP":     "127.0.0.1",
			},
		},
		{
			Name: "Host Override Chain",
			Headers: map[string]string{
				"Host":             "localhost",
				"X-Http-Host":      "localhost",
				"X-Host":           "localhost",
				"X-Forwarded-Host": "localhost",
			},
		},
		{
			Name: "Protocol Confusion",
			Headers: map[string]string{
				"X-Forwarded-Proto": "http",
				"X-Forwarded-SSL":   "on",
				"Front-End-Https":   "on",
				"Protocol":          "http/1.0",
			},
		},
	}
}

func BuildHeaderChain(name string, values map[string]string) string {
	var parts []string
	for k, v := range values {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return strings.Join(parts, ", ")
}
