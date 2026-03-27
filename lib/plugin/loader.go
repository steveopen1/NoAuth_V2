package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"runtime"
	"strings"
	"sync"
)

type Plugin interface {
	Name() string
	Version() string
	Execute(ctx *ScanContext) error
	Init(config map[string]interface{}) error
}

type ScanContext struct {
	TargetURL    string
	NoAuthURL    string
	AuthURL      string
	Method       string
	Path         string
	Headers      map[string]string
	Body         string
	ResponseCode int
	ResponseBody []byte
	Result       *ScanResult
}

type ScanResult struct {
	Bypass  bool
	Tech    string
	Risk    string
	Message string
}

var (
	plugins = make(map[string]Plugin)
	mu      sync.RWMutex
)

func Register(name string, p Plugin) error {
	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}
	if p == nil {
		return fmt.Errorf("plugin cannot be nil")
	}
	mu.Lock()
	defer mu.Unlock()
	plugins[name] = p
	return nil
}

func Get(name string) (Plugin, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := plugins[name]
	return p, ok
}

func List() []string {
	mu.RLock()
	defer mu.RUnlock()
	var names []string
	for name := range plugins {
		names = append(names, name)
	}
	return names
}

func Unregister(name string) bool {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := plugins[name]; ok {
		delete(plugins, name)
		return true
	}
	return false
}

func LoadFromFile(path string) (Plugin, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin file: %w", err)
	}

	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return nil, fmt.Errorf("plugin symbol not found: %w", err)
	}

	pl, ok := symPlugin.(Plugin)
	if !ok {
		return nil, fmt.Errorf("plugin does not implement Plugin interface")
	}

	Register(pl.Name(), pl)
	return pl, nil
}

func LoadFromDir(dirPath string) ([]Plugin, error) {
	var loaded []Plugin

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin directory: %w", err)
	}

	ext := pluginExt()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ext) {
			path := filepath.Join(dirPath, entry.Name())
			p, err := LoadFromFile(path)
			if err != nil {
				continue
			}
			loaded = append(loaded, p)
		}
	}

	return loaded, nil
}

func pluginExt() string {
	switch runtime.GOOS {
	case "windows":
		return ".dll"
	case "darwin":
		return ".dylib"
	default:
		return ".so"
	}
}

func IsValidPlugin(path string) bool {
	p, err := plugin.Open(path)
	if err != nil {
		return false
	}

	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return false
	}

	_, ok := symPlugin.(Plugin)
	return ok
}

func GetAll() map[string]Plugin {
	mu.RLock()
	defer mu.RUnlock()

	result := make(map[string]Plugin)
	for k, v := range plugins {
		result[k] = v
	}
	return result
}

func Clear() {
	mu.Lock()
	defer mu.Unlock()
	plugins = make(map[string]Plugin)
}

var (
	ErrPluginNotFound = errors.New("plugin not found")
	ErrInvalidPlugin  = errors.New("invalid plugin")
)
