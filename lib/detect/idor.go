package detect

import (
	"fmt"
	"regexp"
	"strings"
)

type IDORDetector struct {
	ParamPatterns []*regexp.Regexp
}

type IDORTest struct {
	OriginalURL   string
	ParamName     string
	OriginalValue string
	TestValue     string
	Description   string
}

func NewIDORDetector() *IDORDetector {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(id|user_id|userid|user-id|account_id|account_id|profile_id|profile-id|member_id|member-id)`),
		regexp.MustCompile(`(?i)(order_id|order-id|transaction_id|transaction-id|ref|reference_id|ref-id|invoice_id|invoice-id)`),
		regexp.MustCompile(`(?i)(document_id|document-id|file_id|file-id|asset_id|asset-id|resource_id|resource-id)`),
		regexp.MustCompile(`(?i)(session_id|session-id|token|sess|uuid|guid|customer_id|customer-id|client_id|client-id)`),
		regexp.MustCompile(`(?i)(product_id|product-id|item_id|item-id|sku|book_id|book-id|post_id|post-id|article_id|article-id)`),
	}

	return &IDORDetector{ParamPatterns: patterns}
}

func (d *IDORDetector) DetectPredictableIDs(url string) []IDORTest {
	var tests []IDORTest

	paramValues := extractURLParams(url)
	for paramName, originalValue := range paramValues {
		if d.isPredictableIDPattern(paramName) {
			testValues := d.generateTestValues(paramName, originalValue)
			for _, testValue := range testValues {
				tests = append(tests, IDORTest{
					OriginalURL:   url,
					ParamName:     paramName,
					OriginalValue: originalValue,
					TestValue:     testValue,
					Description:   fmt.Sprintf("IDOR test: %s changed from %s to %s", paramName, originalValue, testValue),
				})
			}
		}
	}

	return tests
}

func (d *IDORDetector) isPredictableIDPattern(paramName string) bool {
	lowerName := strings.ToLower(paramName)
	for _, pattern := range d.ParamPatterns {
		if pattern.MatchString(lowerName) {
			return true
		}
	}
	return false
}

func (d *IDORDetector) generateTestValues(paramName, currentValue string) []string {
	var tests []string
	lowerName := strings.ToLower(paramName)

	if strings.Contains(lowerName, "id") || strings.Contains(lowerName, "_id") {
		if isNumeric(currentValue) {
			num := parseIntSafe(currentValue)
			if num > 0 {
				tests = append(tests, "1")
				tests = append(tests, "0")
				tests = append(tests, fmt.Sprintf("%d", num+1))
				tests = append(tests, fmt.Sprintf("%d", num-1))
				tests = append(tests, "999999")
				tests = append(tests, "999999999")
			}
		}

		if isUUID(currentValue) {
			tests = append(tests, generateTestUUID())
			tests = append(tests, "00000000-0000-0000-0000-000000000000")
			tests = append(tests, "550e8400-e29b-41d4-a716-446655440000")
		}
	}

	if strings.Contains(lowerName, "user") || strings.Contains(lowerName, "member") || strings.Contains(lowerName, "customer") {
		tests = append(tests, "admin")
		tests = append(tests, "root")
		tests = append(tests, "1")
		tests = append(tests, "0")
	}

	if strings.Contains(lowerName, "order") || strings.Contains(lowerName, "transaction") || strings.Contains(lowerName, "invoice") {
		tests = append(tests, "1")
		tests = append(tests, "ORD-000001")
		tests = append(tests, "TRX-000001")
	}

	return tests
}

func extractURLParams(url string) map[string]string {
	params := make(map[string]string)

	parts := strings.Split(url, "?")
	if len(parts) < 2 {
		return params
	}

	queryParts := strings.Split(parts[1], "&")
	for _, part := range queryParts {
		kv := strings.Split(part, "=")
		if len(kv) >= 1 {
			key := kv[0]
			value := ""
			if len(kv) >= 2 {
				value = kv[1]
			}
			params[key] = value
		}
	}

	return params
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func parseIntSafe(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func isUUID(s string) bool {
	uuidPattern := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return uuidPattern.MatchString(s)
}

func generateTestUUID() string {
	return "00000000-0000-0000-0000-000000000001"
}
