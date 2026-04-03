package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/iantsysog/sing-rule/adapter"
	"github.com/iantsysog/sing-rule/option"
	"github.com/sagernet/sing/common/buf"
)

var _ adapter.Source = (*Local)(nil)

type Local struct {
	root         string
	pathTemplate *template.Template
}

func NewLocal(ctx context.Context, options option.SourceOptions) (*Local, error) {
	_ = ctx
	root := strings.TrimSpace(options.LocalOptions.Root)
	if root == "" {
		root = "."
	}
	root = filepath.Clean(root)
	pathTemplate := template.New("local_path").Funcs(template.FuncMap{
		"toLower": strings.ToLower,
		"toUpper": strings.ToUpper,
	})
	if _, err := pathTemplate.Parse(options.LocalOptions.Path); err != nil {
		return nil, err
	}
	return &Local{root: root, pathTemplate: pathTemplate}, nil
}

func (s *Local) Path(urlParams map[string]string) (sourcePath string, err error) {
	if s == nil || s.pathTemplate == nil {
		return "", os.ErrInvalid
	}
	pathBuffer := buf.New()
	defer pathBuffer.Release()
	if err = s.pathTemplate.Execute(pathBuffer, urlParams); err != nil {
		return "", err
	}
	relativePath := filepath.Clean(string(pathBuffer.Bytes()))
	if relativePath == "." {
		return "", errors.New("invalid local source path")
	}
	if filepath.IsAbs(relativePath) {
		return "", errors.New("invalid local source path: absolute path is not allowed")
	}

	absoluteRoot, err := filepath.Abs(s.root)
	if err != nil {
		return "", err
	}
	absolutePath, err := filepath.Abs(filepath.Join(absoluteRoot, relativePath))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absoluteRoot, absolutePath)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid local source path: path escapes root")
	}
	return absolutePath, nil
}

func (s *Local) LastUpdated(path string) time.Time {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fileInfo.ModTime()
}

func (s *Local) Fetch(path string, requestBody adapter.FetchRequestBody) (*adapter.FetchResponseBody, error) {
	_ = requestBody
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &adapter.FetchResponseBody{Content: content, LastUpdated: fileInfo.ModTime()}, nil
}
