package adapter

import (
	"context"

	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/option"
)

type Convertor interface {
	Type() string
	ContentType(options ConvertOptions) string
	From(ctx context.Context, content []byte, options ConvertOptions) ([]Rule, error)
	To(ctx context.Context, contentRules []Rule, options ConvertOptions) ([]byte, error)
}

type ConvertOptions struct {
	Options  option.ConvertOptions
	Metadata C.Metadata
}
