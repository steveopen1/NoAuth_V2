package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type GraphQLBypassCase struct {
	method      string
	url         string
	headers     map[string]string
	body        string
	contentType string
	desc        string
}

func BuildGraphQLBypassCases(baseURL string) []GraphQLBypassCase {
	var cases []GraphQLBypassCase

	graphqlEndpoints := []string{
		"/graphql",
		"/api/graphql",
		"/api/v1/graphql",
		"/query",
		"/graphql/v1",
		"/graphql/v2",
		"/api/gql",
		"/gql",
		"/graphiql",
		"/playground",
	}

	introspectionQueries := buildIntrospectionQueries()

	for _, endpoint := range graphqlEndpoints {
		url := strings.TrimSuffix(baseURL, "/") + endpoint

		for _, query := range introspectionQueries {
			cases = append(cases, GraphQLBypassCase{
				method:      "POST",
				url:         url,
				headers:     map[string]string{},
				body:        query.body,
				contentType: "application/json",
				desc:        query.desc,
			})
		}

		cases = append(cases, GraphQLBypassCase{
			method:      "POST",
			url:         url,
			headers:     map[string]string{},
			body:        `{"query":"{ __schema { types { name } } }"}`,
			contentType: "application/json",
			desc:        "GraphQL[introspection __schema]",
		})

		cases = append(cases, GraphQLBypassCase{
			method:      "GET",
			url:         url + "?query={__schema{types{name}}}",
			headers:     map[string]string{},
			body:        "",
			contentType: "",
			desc:        "GraphQL[introspection GET]",
		})

		cases = append(cases, GraphQLBypassCase{
			method:      "POST",
			url:         url,
			headers:     map[string]string{},
			body:        `{"query":"mutation { __typename }"}`,
			contentType: "application/json",
			desc:        "GraphQL[mutation __typename]",
		})

		cases = append(cases, GraphQLBypassCase{
			method:      "POST",
			url:         url,
			headers:     map[string]string{},
			body:        `{"query":"{ __type(name: \"User\") { fields { name type { name kind } } } }"}`,
			contentType: "application/json",
			desc:        "GraphQL[introspection User type]",
		})

		batchQueries := []string{
			`{"query":"{ a: users { id } }{ b: users { email } }"}`,
			`[{"query":"{ users { id } "},{"query":"{ users { email } }"}]`,
			`{"query":"__schema { types { name } } __type(name: \"User\") { fields { name } }"}`,
		}
		for i, q := range batchQueries {
			cases = append(cases, GraphQLBypassCase{
				method:      "POST",
				url:         url,
				headers:     map[string]string{},
				body:        q,
				contentType: "application/json",
				desc:        fmt.Sprintf("GraphQL[batch query %d]", i+1),
			})
		}

		possibleQueryFields := []string{
			"users", "user", "accounts", "account",
			"posts", "post", "articles", "article",
			"products", "product", "orders", "order",
			"customers", "customer", "payments", "payment",
			"admins", "admin", "roles", "permissions",
			"secrets", "keys", "credentials", "config",
			"files", "documents", "settings", "profiles",
		}
		for _, field := range possibleQueryFields {
			cases = append(cases, GraphQLBypassCase{
				method:      "POST",
				url:         url,
				headers:     map[string]string{},
				body:        fmt.Sprintf(`{"query":"{ %s { id } }"}`, field),
				contentType: "application/json",
				desc:        fmt.Sprintf("GraphQL[query %s.id]", field),
			})
			cases = append(cases, GraphQLBypassCase{
				method:      "POST",
				url:         url,
				headers:     map[string]string{},
				body:        fmt.Sprintf(`{"query":"{ %s { email password } }"}`, field),
				contentType: "application/json",
				desc:        fmt.Sprintf("GraphQL[query %s.email/password]", field),
			})
			cases = append(cases, GraphQLBypassCase{
				method:      "POST",
				url:         url,
				headers:     map[string]string{},
				body:        fmt.Sprintf(`{"query":"{ %s { * } }"}`, field),
				contentType: "application/json",
				desc:        fmt.Sprintf("GraphQL[query %s.*]", field),
			})
		}

		cases = append(cases, GraphQLBypassCase{
			method:      "POST",
			url:         url,
			headers:     map[string]string{},
			body:        `{"query":"{ __schema { queryType { name fields { name args { name type { name } } } } } }"}`,
			contentType: "application/json",
			desc:        "GraphQL[introspection full query]",
		})

		altIntrospectionQueries := []string{
			`{"query":"{ introspection { types { name } } }"}`,
			`{"query":"{ _introspection { schema { types { name } } } }"}`,
			`{"query":"{ __type { name fields { name } } }"}`,
		}
		for i, q := range altIntrospectionQueries {
			cases = append(cases, GraphQLBypassCase{
				method:      "POST",
				url:         url,
				headers:     map[string]string{},
				body:        q,
				contentType: "application/json",
				desc:        fmt.Sprintf("GraphQL[alt introspection %d]", i+1),
			})
		}

		unionTypes := []string{
			`{"query":"{ __type(name: \"User\") { possibleTypes { name } } }"}`,
			`{"query":"{ __union { name kind possibleTypes { name } } }"}`,
		}
		for i, q := range unionTypes {
			cases = append(cases, GraphQLBypassCase{
				method:      "POST",
				url:         url,
				headers:     map[string]string{},
				body:        q,
				contentType: "application/json",
				desc:        fmt.Sprintf("GraphQL[union query %d]", i+1),
			})
		}

		contentTypeVariants := []string{
			"application/json",
			"application/graphql",
			"text/plain",
			"application/x-www-form-urlencoded",
		}
		for _, ct := range contentTypeVariants {
			cases = append(cases, GraphQLBypassCase{
				method:      "POST",
				url:         url,
				headers:     map[string]string{},
				body:        `{"query":"{ __typename }"}`,
				contentType: ct,
				desc:        fmt.Sprintf("GraphQL[content-type %s]", ct),
			})
		}
	}

	return cases
}

type introspectionQuery struct {
	body string
	desc string
}

func buildIntrospectionQueries() []introspectionQuery {
	return []introspectionQuery{
		{
			body: `{"query":"{ __schema { queryType { name } } }"}`,
			desc: "GraphQL[introspection queryType name]",
		},
		{
			body: `{"query":"{ __schema { types { name kind } } }"}`,
			desc: "GraphQL[introspection all types]",
		},
		{
			body: `{"query":"{ __schema { directives { name locations args { name type { name } } } } }"}`,
			desc: "GraphQL[introspection directives]",
		},
		{
			body: `{"query":"{ __type(name: \"Query\") { fields { name type { name kind ofType { name kind } } args { name type { name kind } defaultValue } } } }"}`,
			desc: "GraphQL[introspection Query fields full]",
		},
		{
			body: `{"query":"{ __type(name: \"Mutation\") { fields { name type { name kind } args { name type { name kind } } } } }"}`,
			desc: "GraphQL[introspection Mutation fields]",
		},
		{
			body: `{"query":"{ __type(name: \"Subscription\") { fields { name type { name kind } args { name } } } }"}`,
			desc: "GraphQL[introspection Subscription fields]",
		},
		{
			body: `{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}`,
			desc: "GraphQL[introspection all types with fields]",
		},
		{
			body: `{"query":"{ __type(name: \"User\") { name fields { name type { name kind ofType { name } } } } }"}`,
			desc: "GraphQL[introspection User type fields]",
		},
		{
			body: `{"query":"{ __type(name: \"Int\") { name kind description } }"}`,
			desc: "GraphQL[introspection scalar Int]",
		},
		{
			body: `{"query":"{ __schema { types { name description fields { name description type { name } } } } }"}`,
			desc: "GraphQL[introspection with descriptions]",
		},
	}
}

func SendGraphQLRequest(url string, body string, contentType string, headers map[string]string) (int, string, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}

	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := HttpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(respBody), nil
}

type GraphQLResponse struct {
	Data   interface{}    `json:"data,omitempty"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

type GraphQLError struct {
	Message   string        `json:"message"`
	Path      []interface{} `json:"path,omitempty"`
	Locations []Location    `json:"locations,omitempty"`
}

type Location struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

func ParseGraphQLResponse(body []byte) (bool, bool, []string) {
	var resp GraphQLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, false, nil
	}

	hasData := resp.Data != nil
	hasErrors := len(resp.Errors) > 0

	var sensitiveFields []string
	if hasData {
		sensitiveFields = extractSensitiveFields(resp.Data, "", sensitiveFields)
	}

	if hasErrors {
		var errorMessages []string
		for _, err := range resp.Errors {
			if err.Message != "" {
				errorMessages = append(errorMessages, err.Message)
			}
			if len(err.Locations) > 0 {
				for _, loc := range err.Locations {
					sensitiveFields = append(sensitiveFields, fmt.Sprintf("Location: line %d, col %d", loc.Line, loc.Column))
				}
			}
		}
		return hasData, hasErrors, errorMessages
	}

	return hasData, hasErrors, nil
}

func extractSensitiveFields(data interface{}, path string, fields []string) []string {
	switch v := data.(type) {
	case map[string]interface{}:
		sensitiveKeys := []string{
			"password", "passwd", "pwd", "secret", "token",
			"api_key", "apikey", "private", "credential",
			"email", "phone", "address", "ssn", "credit",
		}
		for key, val := range v {
			currentPath := key
			if path != "" {
				currentPath = path + "." + key
			}
			for _, sensitive := range sensitiveKeys {
				if strings.Contains(strings.ToLower(key), sensitive) {
					fields = append(fields, currentPath)
				}
			}
			fields = extractSensitiveFields(val, currentPath, fields)
		}
	case []interface{}:
		for i, item := range v {
			currentPath := fmt.Sprintf("%s[%d]", path, i)
			fields = extractSensitiveFields(item, currentPath, fields)
		}
	}
	return fields
}

func DetectGraphQL(url string) bool {
	testURL := strings.TrimSuffix(url, "/")

	graphqlEndpoints := []string{
		"/graphql",
		"/api/graphql",
		"/query",
	}

	for _, endpoint := range graphqlEndpoints {
		testUrl := testURL + endpoint
		body := `{"query":"{ __typename }"}`

		req, err := http.NewRequest("POST", testUrl, bytes.NewBufferString(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := DoWithRetry(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			var graphqlResp GraphQLResponse
			if json.Unmarshal(respBody, &graphqlResp) == nil {
				if graphqlResp.Data != nil || len(graphqlResp.Errors) > 0 {
					return true
				}
			}
		}
	}

	altBody := `{"query":"{ __schema { queryType { name } } }"}`
	for _, endpoint := range graphqlEndpoints {
		testUrl := testURL + endpoint
		req, err := http.NewRequest("POST", testUrl, bytes.NewBufferString(altBody))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := DoWithRetry(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 400 {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			var graphqlResp GraphQLResponse
			if json.Unmarshal(respBody, &graphqlResp) == nil {
				if graphqlResp.Data != nil {
					return true
				}
			}
		}
	}

	return false
}
