package convertor

import (
	"bytes"
	"context"

	"github.com/iantsysog/sing-rule/adapter"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing/common"
)

var _ adapter.Convertor = (*RuleSetBinary)(nil)

type RuleSetBinary struct{}

func (s *RuleSetBinary) Type() string {
	return C.ConvertorTypeRuleSetBinary
}

func (s *RuleSetBinary) ContentType(_ adapter.ConvertOptions) string {
	return "application/octet-stream"
}

func (s *RuleSetBinary) From(ctx context.Context, content []byte, _ adapter.ConvertOptions) ([]adapter.Rule, error) {
	options, err := srs.Read(bytes.NewReader(content), true)
	if err != nil {
		return nil, err
	}
	return common.Map(options.Options.Rules, adapter.RuleFrom), nil
}

func (s *RuleSetBinary) To(ctx context.Context, contentRules []adapter.Rule, options adapter.ConvertOptions) ([]byte, error) {
	ruleSet, err := buildRuleSet(ctx, contentRules, options)
	if err != nil {
		return nil, err
	}
	buffer := new(bytes.Buffer)
	err = srs.Write(buffer, ruleSet.Options, ruleSet.Version)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
