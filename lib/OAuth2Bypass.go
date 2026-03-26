package lib

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	urlpkg "net/url"
	"strings"
)

type OAuth2BypassCase struct {
	method  string
	url     string
	headers map[string]string
	body    string
	desc    string
}

func BuildOAuth2BypassCases(baseURL string) []OAuth2BypassCase {
	var cases []OAuth2BypassCase

	oauthEndpoints := []string{
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/access_token",
		"/api/oauth/authorize",
		"/api/oauth/token",
		"/auth/oauth/authorize",
		"/login/oauth/authorize",
	}

	redirectURI := "https://attacker.com/callback"
	attackerDomain := "attacker.com"

	for _, endpoint := range oauthEndpoints {
		fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

		cases = append(cases, OAuth2BypassCase{
			method: "GET",
			url:    fullURL + "?response_type=code&client_id=test&redirect_uri=" + url.QueryEscape(redirectURI),
			desc:   "OAuth2[redirect_uri bypass - external domain]",
		})

		cases = append(cases, OAuth2BypassCase{
			method: "GET",
			url:    fullURL + "?response_type=code&client_id=test&redirect_uri=http://" + attackerDomain + "/callback",
			desc:   "OAuth2[redirect_uri http scheme]",
		})

		cases = append(cases, OAuth2BypassCase{
			method: "GET",
			url:    fullURL + "?response_type=token&client_id=test&redirect_uri=" + url.QueryEscape(redirectURI),
			desc:   "OAuth2[implicit flow redirect]",
		})

		localhostURIs := []string{
			"http://localhost/callback",
			"http://127.0.0.1/callback",
			"http://[::1]/callback",
		}
		for _, uri := range localhostURIs {
			cases = append(cases, OAuth2BypassCase{
				method: "GET",
				url:    fullURL + "?response_type=code&client_id=test&redirect_uri=" + url.QueryEscape(uri),
				desc:   fmt.Sprintf("OAuth2[redirect_uri %s]", uri),
			})
		}

		cases = append(cases, OAuth2BypassCase{
			method:  "POST",
			url:     strings.Replace(fullURL, "/authorize", "/token", 1),
			headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			body:    "grant_type=authorization_code&code=test&redirect_uri=https://attacker.com/callback",
			desc:    "OAuth2[token request with forged code]",
		})

		cases = append(cases, OAuth2BypassCase{
			method:  "POST",
			url:     strings.Replace(fullURL, "/authorize", "/token", 1),
			headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			body:    "grant_type=client_credentials&client_id=test&client_secret=test",
			desc:    "OAuth2[client_credentials flow]",
		})

		cases = append(cases, OAuth2BypassCase{
			method:  "POST",
			url:     strings.Replace(fullURL, "/authorize", "/token", 1),
			headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			body:    "grant_type=refresh_token&refresh_token=test",
			desc:    "OAuth2[refresh token reuse]",
		})

		stateBypasses := []string{
			"null",
			"",
			"admin",
			"../../",
		}
		for _, state := range stateBypasses {
			cases = append(cases, OAuth2BypassCase{
				method: "GET",
				url:    fullURL + "?response_type=code&client_id=test&state=" + state + "&redirect_uri=" + url.QueryEscape(redirectURI),
				desc:   fmt.Sprintf("OAuth2[state=%s]", state),
			})
		}

		scopeBypasses := []string{
			"openid profile email",
			"admin read write",
			"offline_access",
			"*",
		}
		for _, scope := range scopeBypasses {
			cases = append(cases, OAuth2BypassCase{
				method: "GET",
				url:    fullURL + "?response_type=code&client_id=test&scope=" + url.QueryEscape(scope) + "&redirect_uri=" + url.QueryEscape(redirectURI),
				desc:   fmt.Sprintf("OAuth2[scope=%s]", scope),
			})
		}
	}

	return cases
}

func DetectOAuth2Vulnerabilities(targetURL string) (bool, []string) {
	var vulnerabilities []string

	if detectOpenRedirect(targetURL) {
		vulnerabilities = append(vulnerabilities, "Open redirect in OAuth flow")
	}

	if detectTokenExposure(targetURL) {
		vulnerabilities = append(vulnerabilities, "Token exposure in URL")
	}

	if detectImplicitGrantHijacking(targetURL) {
		vulnerabilities = append(vulnerabilities, "Implicit grant vulnerable to hijacking")
	}

	if detectAuthorizationCodeReuse(targetURL) {
		vulnerabilities = append(vulnerabilities, "Authorization code reuse possible")
	}

	if detectPKCEBypass(targetURL) {
		vulnerabilities = append(vulnerabilities, "PKCE bypass possible")
	}

	return len(vulnerabilities) > 0, vulnerabilities
}

func detectOpenRedirect(authorizationURL string) bool {
	attackerDomain := "attacker.com"
	testURL := authorizationURL + "?response_type=code&client_id=test&redirect_uri=https://" + attackerDomain + "/callback"

	resp, err := HttpClient.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if strings.Contains(location, attackerDomain) {
		return true
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return strings.Contains(location, attackerDomain)
	}

	return false
}

func detectTokenExposure(authorizationURL string) bool {
	testURL := authorizationURL + "?response_type=token&client_id=test&redirect_uri=https://attacker.com/callback"

	resp, err := HttpClient.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "access_token=") ||
			strings.Contains(location, "id_token=") ||
			strings.Contains(location, "token=") {
			return true
		}
	}

	return false
}

func detectImplicitGrantHijacking(authorizationURL string) bool {
	resp, err := HttpClient.Get(authorizationURL + "?response_type=token&client_id=test")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		bodyStr := strings.ToLower(string(body))

		fragmentParams := []string{"access_token", "id_token", "token_type", "expires_in"}
		for _, param := range fragmentParams {
			if strings.Contains(bodyStr, "#"+param) || strings.Contains(bodyStr, "#access_token") {
				return true
			}
		}
	}

	return false
}

func detectAuthorizationCodeReuse(tokenURL string) bool {
	testCode := "test_authorization_code"

	resp, err := http.PostForm(tokenURL, map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {testCode},
		"redirect_uri":  {"https://attacker.com/callback"},
		"client_id":     {"test"},
		"client_secret": {"test"},
	})
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyStr := strings.ToLower(string(body))

	if strings.Contains(bodyStr, "invalid_grant") || strings.Contains(bodyStr, "code_expired") {
		return false
	}

	if strings.Contains(bodyStr, "access_token") {
		return true
	}

	return false
}

func detectPKCEBypass(authorizationURL string) bool {
	normalURL := authorizationURL + "?response_type=code&client_id=test&code_challenge=test_challenge&code_challenge_method=S256"

	resp, err := HttpClient.Get(normalURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	resp.Body.Close()

	noChallengeURL := authorizationURL + "?response_type=code&client_id=test"

	resp2, err := HttpClient.Get(noChallengeURL)
	if err != nil {
		return false
	}
	defer resp2.Body.Close()

	if resp.StatusCode != resp2.StatusCode {
		return true
	}

	return false
}

type OAuth2FlowTest struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	ClientSecret          string
	RedirectURI           string
}

func (f *OAuth2FlowTest) TestAuthorizationCodeFlow() (bool, string) {
	authURL := f.AuthorizationEndpoint + "?" +
		"response_type=code" +
		"&client_id=" + f.ClientID +
		"&redirect_uri=" + url.QueryEscape(f.RedirectURI) +
		"&scope=openid profile"

	resp, err := HttpClient.Get(authURL)
	if err != nil {
		return false, fmt.Sprintf("Authorization request failed: %v", err)
	}
	defer resp.Body.Close()

	code := resp.Request.URL.Query().Get("code")
	if code == "" {
		location := resp.Header.Get("Location")
		if location != "" {
			u, err := url.Parse(location)
			if err == nil {
				code = u.Query().Get("code")
			}
		}
	}

	if code == "" {
		return false, "No authorization code received"
	}

	tokenResp, err := http.PostForm(f.TokenEndpoint, map[string][]string{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.RedirectURI},
		"client_id":     {f.ClientID},
		"client_secret": {f.ClientSecret},
	})
	if err != nil {
		return false, fmt.Sprintf("Token request failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode == 200 {
		return true, "Authorization code flow works"
	}

	return false, fmt.Sprintf("Token request returned status: %d", tokenResp.StatusCode)
}

func (f *OAuth2FlowTest) TestClientCredentialsFlow() (bool, string) {
	resp, err := http.PostForm(f.TokenEndpoint, map[string][]string{
		"grant_type":    {"client_credentials"},
		"client_id":     {f.ClientID},
		"client_secret": {f.ClientSecret},
		"scope":         {"openid profile"},
	})
	if err != nil {
		return false, fmt.Sprintf("Client credentials request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return true, "Client credentials flow works"
	}

	return false, fmt.Sprintf("Client credentials returned status: %d", resp.StatusCode)
}

func TestOAuth2Security(url string) map[string]bool {
	results := map[string]bool{
		"open_redirect":         false,
		"token_in_url":          false,
		"code_reuse":            false,
		"scope_injection":       false,
		"state_not_verified":    false,
		"redirect_uri_mismatch": false,
	}

	authEndpoints := []string{
		"/oauth/authorize",
		"/oauth/v1/authorize",
		"/authorize",
	}

	tokenEndpoints := []string{
		"/oauth/token",
		"/oauth/v1/token",
		"/token",
	}

	attackerRedirect := "https://evil.com/callback"

	for _, endpoint := range authEndpoints {
		testURL := url + endpoint + "?response_type=code&client_id=test&redirect_uri=" + urlpkg.QueryEscape(attackerRedirect)

		resp, err := HttpClient.Get(testURL)
		if err == nil {
			resp.Body.Close()

			location := resp.Header.Get("Location")
			if strings.Contains(location, "evil.com") {
				results["open_redirect"] = true
			}
		}
	}

	for _, endpoint := range authEndpoints {
		testURL := url + endpoint + "?response_type=token&client_id=test&redirect_uri=" + urlpkg.QueryEscape(attackerRedirect)

		resp, err := HttpClient.Get(testURL)
		if err == nil {
			resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if strings.Contains(location, "#access_token=") || strings.Contains(location, "access_token=") {
					results["token_in_url"] = true
				}
			}
		}
	}

	for _, endpoint := range tokenEndpoints {
		testURL := url + endpoint

		resp, err := http.PostForm(testURL, map[string][]string{
			"grant_type":    {"authorization_code"},
			"code":          {"stolen_code"},
			"redirect_uri":  {attackerRedirect},
			"client_id":     {"test"},
			"client_secret": {"test"},
		})
		if err == nil {
			resp.Body.Close()

			if resp.StatusCode != 400 {
				results["code_reuse"] = true
			}
		}
	}

	return results
}
