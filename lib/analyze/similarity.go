package analyze

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

type Tokenizer interface {
	Tokenize(text []byte) []string
}

type WordTokenizer struct{}

func (t *WordTokenizer) Tokenize(text []byte) []string {
	var tokens []string
	var current []rune

	for _, r := range string(text) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current = append(current, unicode.ToLower(r))
		} else {
			if len(current) > 0 {
				tokens = append(tokens, string(current))
				current = nil
			}
		}
	}

	if len(current) > 0 {
		tokens = append(tokens, string(current))
	}

	return tokens
}

type CharTokenizer struct{}

func (t *CharTokenizer) Tokenize(text []byte) []string {
	var tokens []string
	for _, r := range string(text) {
		tokens = append(tokens, string(r))
	}
	return tokens
}

func JaccardSimilarity(text1, text2 []byte) float64 {
	tokens1 := basicTokenize(string(text1))
	tokens2 := basicTokenize(string(text2))

	if len(tokens1) == 0 && len(tokens2) == 0 {
		return 1.0
	}
	if len(tokens1) == 0 || len(tokens2) == 0 {
		return 0.0
	}

	set1 := make(map[string]bool)
	for _, t := range tokens1 {
		set1[t] = true
	}

	set2 := make(map[string]bool)
	for _, t := range tokens2 {
		set2[t] = true
	}

	intersection := 0
	for t1 := range set1 {
		if set2[t1] {
			intersection++
		}
	}

	union := len(set1) + len(set2) - intersection

	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

func CosineSimilarity(text1, text2 []byte) float64 {
	tokens1 := basicTokenize(string(text1))
	tokens2 := basicTokenize(string(text2))

	if len(tokens1) == 0 && len(tokens2) == 0 {
		return 1.0
	}
	if len(tokens1) == 0 || len(tokens2) == 0 {
		return 0.0
	}

	tf1 := termFrequency(tokens1)
	tf2 := termFrequency(tokens2)

	dotProduct := 0.0
	norm1 := 0.0
	norm2 := 0.0

	for token, freq1 := range tf1 {
		freq2 := tf2[token]
		dotProduct += float64(freq1) * float64(freq2)
		norm1 += float64(freq1) * float64(freq1)
	}

	for _, freq2 := range tf2 {
		norm2 += float64(freq2) * float64(freq2)
	}

	if norm1 == 0 || norm2 == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(norm1) * math.Sqrt(norm2))
}

func SimHash(text []byte, hashBits int) uint64 {
	if hashBits <= 0 {
		hashBits = 64
	}

	tokens := basicTokenize(string(text))
	if len(tokens) == 0 {
		return 0
	}

	v := make([]float64, hashBits)

	for _, token := range tokens {
		hash := hash64(token)
		for i := 0; i < hashBits; i++ {
			bit := (hash >> i) & 1
			if bit == 1 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}

	var result uint64
	for i := 0; i < hashBits; i++ {
		if v[i] > 0 {
			result |= (1 << i)
		}
	}

	return result
}

func HammingDistance(hash1, hash2 uint64) int {
	xor := hash1 ^ hash2
	distance := 0
	for xor > 0 {
		distance++
		xor &= xor - 1
	}
	return distance
}

func basicTokenize(text string) []string {
	var tokens []string
	var current []rune

	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current = append(current, unicode.ToLower(r))
		} else {
			if len(current) > 0 {
				tokens = append(tokens, string(current))
				current = nil
			}
		}
	}

	if len(current) > 0 {
		tokens = append(tokens, string(current))
	}

	return tokens
}

func termFrequency(tokens []string) map[string]int {
	tf := make(map[string]int)
	for _, token := range tokens {
		tf[token]++
	}
	return tf
}

var hashSeed = []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}

func hash64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	for i := 0; i < len(hashSeed); i++ {
		h ^= uint64(hashSeed[i])
		h *= 1099511628211
	}
	return h
}

func SimilarityScore(text1, text2 []byte) float64 {
	jaccard := JaccardSimilarity(text1, text2)
	cosine := CosineSimilarity(text1, text2)
	return (jaccard + cosine) / 2.0
}

func DetectNearDuplicates(texts [][]byte, threshold float64) [][]int {
	if len(texts) <= 1 {
		return nil
	}

	hashes := make([]uint64, len(texts))
	for i, text := range texts {
		hashes[i] = SimHash(text, 64)
	}

	var groups [][]int

	for i := 0; i < len(texts); i++ {
		group := []int{i}
		for j := i + 1; j < len(texts); j++ {
			if HammingDistance(hashes[i], hashes[j]) <= 3 {
				group = append(group, j)
			}
		}
		if len(group) > 1 {
			groups = append(groups, group)
		}
	}

	return groups
}

var loginKeywords = []string{
	"login", "signin", "sign in", "log in", "username", "password",
	"email", "e-mail", "authentication", "authenticate",
	"unauthorized", "forbidden", "access denied", "denied",
	"session", "credential", "login page", "sign in page",
	"please sign in", "please login", "invalid credentials",
	"incorrect password", "wrong password", "incorrect username",
	"account", "user id", "userid", "user id",
	"security", "secure", "logout", "log out",
	"register", "signup", "sign up", "create account",
	"forgot password", "reset password", "recover password",
	"session expired", "session invalid", "token expired",
}

func CalculateLoginScore(body []byte) float64 {
	if len(body) == 0 {
		return 0.0
	}

	lowerBody := strings.ToLower(string(body))
	totalScore := 0.0

	keywordCount := 0
	for _, keyword := range loginKeywords {
		if strings.Contains(lowerBody, keyword) {
			keywordCount++
		}
	}

	totalScore += float64(keywordCount) * 2.0

	formPattern := regexp.MustCompile(`(?i)<form[^>]*>`)
	if formPattern.Match(body) {
		totalScore += 5.0
	}

	inputPattern := regexp.MustCompile(`(?i)<input[^>]*type=["']password["'][^>]*>`)
	if inputPattern.Match(body) {
		totalScore += 10.0
	}

	redirectPattern := regexp.MustCompile(`(?i)(login|signin|auth)`)
	if redirectPattern.MatchString(lowerBody) {
		totalScore += 3.0
	}

	statusPattern := regexp.MustCompile(`(?i)(401|403|unauthorized|forbidden|access denied)`)
	if statusPattern.Match(body) {
		totalScore += 5.0
	}

	maxScore := 50.0
	normalizedScore := math.Min(totalScore, maxScore) / maxScore

	return normalizedScore
}
