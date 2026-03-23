package source

import (
	"context"
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
	pathTemplate *template.Template
}

func NewLocal(ctx context.Context, options option.SourceOptions) (*Local, error) {
	_ = ctx
	pathTemplate := template.New("local path")
	pathTemplate.Funcs(template.FuncMap{
		"toLower": strings.ToLower,
		"toUpper": strings.ToUpper,
	})
	_, err := pathTemplate.Parse(options.LocalOptions.Path)
	if err != nil {
		return nil, err
	}
	return &Local{
		pathTemplate: pathTemplate,
	}, nil
}

func (s *Local) Path(urlParams map[string]string) (sourcePath string, err error) {
	if s == nil || s.pathTemplate == nil {
		return "", os.ErrInvalid
	}
	pathBuffer := buf.New()
	defer pathBuffer.Release()
	err = s.pathTemplate.Execute(pathBuffer, urlParams)
	if err != nil {
		return
	}
	sourcePath = filepath.Clean(string(pathBuffer.Bytes()))
	return
}

func (s *Local) LastUpdated(path string) time.Time {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fileInfo.ModTime()
}

func (s *Local) Fetch(path string, requestBody adapter.FetchRequestBody) (body *adapter.FetchResponseBody, err error) {
	_ = requestBody
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lastUpdated := s.LastUpdated(path)
	return &adapter.FetchResponseBody{
		Content:     content,
		LastUpdated: lastUpdated,
	}, nil
}
