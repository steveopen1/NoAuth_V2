package types

type ParsedRequest struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	ContentType string
	Raw         string
}

type FuzzVariant struct {
	Name        string
	Type        string
	MutatedURL  string
	Method      string
	Headers     map[string]string
	Body        string
	Description string
}

type ScanResult struct {
	URL            string
	Method         string
	StatusCode     int
	Length         int
	Classification string
	BypassTech     string
	CurlCmd        string
	IsHighRisk     bool
}
