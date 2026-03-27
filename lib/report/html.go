package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type ReportData struct {
	Title       string
	GeneratedAt string
	TargetURL   string
	Summary     ReportSummary
	Results     []ResultItem
}

type ReportSummary struct {
	TotalTests  int
	HighRisk    int
	MediumRisk  int
	LowRisk     int
	Info        int
	BypassCount int
}

type ResultItem struct {
	Method         string
	URL            string
	StatusCode     int
	Length         int
	Classification string
	BypassTech     string
	CurlCmd        string
	IsHighRisk     bool
	RiskLevel      string
}

func GenerateHTMLReport(results []ReportResult, outputPath string, targetURL string) error {
	data := buildReportData(results, targetURL)
	return renderHTML(data, outputPath)
}

type ReportResult struct {
	Method         string
	URL            string
	StatusCode     int
	Length         int
	Classification string
	BypassTech     string
	CurlCmd        string
	IsHighRisk     bool
}

func buildReportData(results []ReportResult, targetURL string) ReportData {
	summary := ReportSummary{}
	items := make([]ResultItem, 0, len(results))

	for _, r := range results {
		item := ResultItem{
			Method:         r.Method,
			URL:            truncateURL(r.URL, 80),
			StatusCode:     r.StatusCode,
			Length:         r.Length,
			Classification: r.Classification,
			BypassTech:     r.BypassTech,
			CurlCmd:        escapeHtml(r.CurlCmd),
			IsHighRisk:     r.IsHighRisk,
		}

		if strings.Contains(r.Classification, "高") || strings.Contains(r.Classification, "high") {
			item.RiskLevel = "high"
			summary.HighRisk++
		} else if strings.Contains(r.Classification, "中") || strings.Contains(r.Classification, "medium") {
			item.RiskLevel = "medium"
			summary.MediumRisk++
		} else if strings.Contains(r.Classification, "低") || strings.Contains(r.Classification, "low") {
			item.RiskLevel = "low"
			summary.LowRisk++
		} else {
			item.RiskLevel = "info"
			summary.Info++
		}

		if r.IsHighRisk {
			summary.BypassCount++
		}

		summary.TotalTests++
		items = append(items, item)
	}

	return ReportData{
		Title:       "NoAuth V2 - Authorization Bypass Scan Report",
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		TargetURL:   targetURL,
		Summary:     summary,
		Results:     items,
	}
}

func renderHTML(data ReportData, outputPath string) error {
	html := generateHTML(data)
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(html)
	return err
}

func generateHTML(data ReportData) string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NoAuth V2 - Authorization Bypass Scan Report</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #1a2332, #2d3748); border-radius: 12px; }
        .header h1 { font-size: 28px; margin-bottom: 10px; color: #58a6ff; }
        .header .meta { color: #8b949e; font-size: 14px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .summary-card { background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; }
        .summary-card .label { color: #8b949e; font-size: 12px; text-transform: uppercase; margin-bottom: 5px; }
        .summary-card .value { font-size: 32px; font-weight: bold; }
        .summary-card .value.high { color: #f85149; }
        .summary-card .value.medium { color: #d29922; }
        .summary-card .value.low { color: #3fb950; }
        .summary-card .value.info { color: #58a6ff; }
        .chart-section { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .chart-card { background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; }
        .chart-card h3 { font-size: 16px; margin-bottom: 15px; color: #e6edf3; }
        #pieChart, #trendChart { width: 100%; height: 300px; }
        .filters { background: #161b22; padding: 15px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #30363d; display: flex; gap: 10px; flex-wrap: wrap; }
        .filter-btn { padding: 8px 16px; border: 1px solid #30363d; background: #21262d; color: #e6edf3; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
        .filter-btn:hover { background: #30363d; }
        .filter-btn.active { background: #238636; border-color: #238636; }
        .search-box { flex: 1; min-width: 200px; }
        .search-box input { width: 100%; padding: 8px 12px; background: #21262d; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; }
        table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #30363d; }
        th { background: #21262d; color: #8b949e; font-weight: 600; font-size: 12px; text-transform: uppercase; }
        tr:hover { background: #1c2128; }
        tr.high-risk { background: rgba(248, 81, 73, 0.1); }
        tr.medium-risk { background: rgba(210, 153, 34, 0.1); }
        .risk-badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .risk-badge.high { background: #f85149; color: white; }
        .risk-badge.medium { background: #d29922; color: white; }
        .risk-badge.low { background: #3fb950; color: white; }
        .risk-badge.info { background: #58a6ff; color: white; }
        .method { font-family: monospace; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
        .method.get { background: #238636; }
        .method.post { background: #1f6feb; }
        .method.put { background: #d29922; }
        .method.delete { background: #f85149; }
        .method.patch { background: #a371f7; }
        .url { font-family: monospace; font-size: 13px; word-break: break-all; color: #58a6ff; }
        .no-results { text-align: center; padding: 40px; color: #8b949e; }
        @media (max-width: 768px) { .chart-section { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>NoAuth V2 - Authorization Bypass Scan Report</h1>
            <div class="meta">
                <p>Target: <strong>` + data.TargetURL + `</strong></p>
                <p>Generated: ` + data.GeneratedAt + `</p>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <div class="label">Total Tests</div>
                <div class="value">` + fmt.Sprintf("%d", data.Summary.TotalTests) + `</div>
            </div>
            <div class="summary-card">
                <div class="label">High Risk</div>
                <div class="value high">` + fmt.Sprintf("%d", data.Summary.HighRisk) + `</div>
            </div>
            <div class="summary-card">
                <div class="label">Medium Risk</div>
                <div class="value medium">` + fmt.Sprintf("%d", data.Summary.MediumRisk) + `</div>
            </div>
            <div class="summary-card">
                <div class="label">Low Risk</div>
                <div class="value low">` + fmt.Sprintf("%d", data.Summary.LowRisk) + `</div>
            </div>
            <div class="summary-card">
                <div class="label">Bypass Confirmed</div>
                <div class="value high">` + fmt.Sprintf("%d", data.Summary.BypassCount) + `</div>
            </div>
        </div>

        <div class="chart-section">
            <div class="chart-card">
                <h3>Risk Distribution</h3>
                <div id="pieChart"></div>
            </div>
            <div class="chart-card">
                <h3>Vulnerability Trends</h3>
                <div id="trendChart"></div>
            </div>
        </div>

        <div class="filters">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search by URL or technique..." onkeyup="filterTable()">
            </div>
            <button class="filter-btn active" onclick="filterByRisk('all')">All</button>
            <button class="filter-btn" onclick="filterByRisk('high')">High</button>
            <button class="filter-btn" onclick="filterByRisk('medium')">Medium</button>
            <button class="filter-btn" onclick="filterByRisk('low')">Low</button>
        </div>

        <table id="resultsTable">
            <thead>
                <tr>
                    <th>Method</th>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Length</th>
                    <th>Classification</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody id="tableBody">`)

	for _, r := range data.Results {
		rowClass := ""
		if r.RiskLevel == "high" {
			rowClass = "high-risk"
		} else if r.RiskLevel == "medium" {
			rowClass = "medium-risk"
		}

		sb.WriteString(`<tr class="` + rowClass + `" data-risk="` + r.RiskLevel + `">`)
		sb.WriteString(`<td><span class="method ` + strings.ToLower(r.Method) + `">` + r.Method + `</span></td>`)
		sb.WriteString(`<td class="url" title="` + r.URL + `">` + r.URL + `</td>`)
		sb.WriteString(`<td>` + fmt.Sprintf("%d", r.StatusCode) + `</td>`)
		sb.WriteString(`<td>` + fmt.Sprintf("%d", r.Length) + `</td>`)
		sb.WriteString(`<td>` + r.Classification + `</td>`)
		sb.WriteString(`<td><span class="risk-badge ` + r.RiskLevel + `">` + r.RiskLevel + `</span></td>`)
		sb.WriteString(`</tr>`)
	}

	sb.WriteString(`</tbody>
        </table>

        <div id="noResults" class="no-results" style="display:none;">No matching results found</div>
    </div>

    <script>
        var pieChart = echarts.init(document.getElementById('pieChart'));
        pieChart.setOption({
            tooltip: { trigger: 'item' },
            legend: { orient: 'vertical', left: 'left', textStyle: { color: '#e6edf3' } },
            series: [{
                name: 'Risk Level',
                type: 'pie',
                radius: '60%',
                data: [
                    { value: ` + fmt.Sprintf("%d", data.Summary.HighRisk) + `, name: 'High Risk', itemStyle: { color: '#f85149' } },
                    { value: ` + fmt.Sprintf("%d", data.Summary.MediumRisk) + `, name: 'Medium Risk', itemStyle: { color: '#d29922' } },
                    { value: ` + fmt.Sprintf("%d", data.Summary.LowRisk) + `, name: 'Low Risk', itemStyle: { color: '#3fb950' } },
                    { value: ` + fmt.Sprintf("%d", data.Summary.Info) + `, name: 'Info', itemStyle: { color: '#58a6ff' } }
                ],
                emphasis: { itemStyle: { shadowBlur: 10, shadowOffsetX: 0, shadowColor: 'rgba(0, 0, 0, 0.5)' } }
            }]
        });

        var trendChart = echarts.init(document.getElementById('trendChart'));
        trendChart.setOption({
            tooltip: { trigger: 'axis' },
            xAxis: { type: 'category', data: ['Week 1', 'Week 2', 'Week 3', 'Week 4'], axisLine: { lineStyle: { color: '#30363d' } }, axisLabel: { color: '#8b949e' } },
            yAxis: { type: 'value', axisLine: { lineStyle: { color: '#30363d' } }, axisLabel: { color: '#8b949e' }, splitLine: { lineStyle: { color: '#21262d' } } },
            series: [
                { name: 'Bypasses', type: 'line', smooth: true, data: [0, 0, ` + fmt.Sprintf("%d", data.Summary.BypassCount) + `, 0], lineStyle: { color: '#f85149' }, itemStyle: { color: '#f85149' }, areaStyle: { color: 'rgba(248, 81, 73, 0.2)' } },
                { name: 'Total Tests', type: 'bar', data: [0, 0, ` + fmt.Sprintf("%d", data.Summary.TotalTests) + `, 0], barWidth: '30%', itemStyle: { color: '#58a6ff' } }
            ],
            grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true }
        });

        var currentFilter = 'all';

        function filterByRisk(risk) {
            currentFilter = risk;
            document.querySelectorAll('.filter-btn').forEach(function(btn) { btn.classList.remove('active'); });
            event.target.classList.add('active');
            filterTable();
        }

        function filterTable() {
            var searchText = document.getElementById('searchInput').value.toLowerCase();
            var rows = document.querySelectorAll('#tableBody tr');
            var visibleCount = 0;

            rows.forEach(function(row) {
                var risk = row.getAttribute('data-risk');
                var text = row.textContent.toLowerCase();
                var matchesSearch = text.indexOf(searchText) !== -1;
                var matchesRisk = currentFilter === 'all' || risk === currentFilter;

                if (matchesSearch && matchesRisk) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });

            document.getElementById('noResults').style.display = visibleCount === 0 ? 'block' : 'none';
        }

        window.addEventListener('resize', function() {
            pieChart.resize();
            trendChart.resize();
        });
    </script>
</body>
</html>`)

	return sb.String()
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen] + "..."
}

func escapeHtml(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func ExportResultsToJSON(results interface{}, outputPath string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0o644)
}
