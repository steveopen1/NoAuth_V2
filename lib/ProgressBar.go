package lib

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type ProgressBar struct {
	Total     int64
	Completed int64
	StartTime time.Time
	Mu        sync.Mutex
	Name      string
}

func NewProgressBar(total int, name string) *ProgressBar {
	return &ProgressBar{
		Total:     int64(total),
		StartTime: time.Now(),
		Name:      name,
	}
}

func (p *ProgressBar) Increment() {
	atomic.AddInt64(&p.Completed, 1)
}

func (p *ProgressBar) Set(completed int) {
	atomic.StoreInt64(&p.Completed, int64(completed))
}

func (p *ProgressBar) GetProgress() (completed int64, total int64) {
	return atomic.LoadInt64(&p.Completed), p.Total
}

func (p *ProgressBar) Percentage() float64 {
	if p.Total == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&p.Completed)) / float64(p.Total) * 100
}

func (p *ProgressBar) ETA() time.Duration {
	elapsed := time.Since(p.StartTime)
	completed := atomic.LoadInt64(&p.Completed)
	if completed == 0 {
		return 0
	}
	rate := float64(completed) / elapsed.Seconds()
	if rate == 0 {
		return 0
	}
	remaining := p.Total - completed
	return time.Duration(float64(remaining)/rate) * time.Second
}

func (p *ProgressBar) Draw() {
	completed, total := p.GetProgress()
	percentage := p.Percentage()
	elapsed := time.Since(p.StartTime)
	eta := p.ETA()

	width := 40
	filled := int(float64(width) * percentage / 100)
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}

	fmt.Printf("\r[%s] %3d%% | %d/%d | elapsed: %s | ETA: %s | %s    ",
		bar,
		int(percentage),
		completed,
		total,
		formatDuration(elapsed),
		formatDuration(eta),
		p.Name)
}

func (p *ProgressBar) Finish() {
	p.Set(int(p.Total))
	p.Draw()
	fmt.Println()
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return "--:--"
	}
	total := int(d.Seconds())
	mins := total / 60
	secs := total % 60
	if mins > 0 {
		return fmt.Sprintf("%02d:%02d", mins, secs)
	}
	return fmt.Sprintf("0:%02d", secs)
}

func DrawSimpleProgress(current, total int, name string) {
	width := 40
	if total == 0 {
		return
	}
	percentage := float64(current) / float64(total) * 100
	filled := int(float64(width) * percentage / 100)
	bar := ""
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}
	fmt.Printf("\r[%s] %3d%% | %d/%d | %s    ", bar, int(percentage), current, total, name)
}

func FinishSimpleProgress(name string) {
	fmt.Printf("\n%s 完成\n", name)
}

var spinnerChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type Spinner struct {
	Message string
	stop    chan bool
}

func NewSpinner(message string) *Spinner {
	return &Spinner{
		Message: message,
		stop:    make(chan bool),
	}
}

func (s *Spinner) Start() {
	go func() {
		i := 0
		for {
			select {
			case <-s.stop:
				return
			default:
				fmt.Printf("\r%s %s", spinnerChars[i%len(spinnerChars)], s.Message)
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

func (s *Spinner) Stop(message string) {
	s.stop <- true
	fmt.Printf("\r%s %s\n", Green("✓"), message)
}

func (s *Spinner) Stopf(format string, args ...interface{}) {
	s.Stop(fmt.Sprintf(format, args...))
}
