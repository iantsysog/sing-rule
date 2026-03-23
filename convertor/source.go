package convertor

import (
	"bytes"
	"context"

	"github.com/iantsysog/sing-rule/adapter"
	"github.com/iantsysog/sing-rule/common/semver"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/convertor/asn"
	boxConstant "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

var _ adapter.Convertor = (*RuleSetSource)(nil)

type RuleSetSource struct{}

var ruleSetV1100 = semver.ParseVersion("1.11.0")
var ruleSetV1000 = semver.ParseVersion("1.10.0")

func (s *RuleSetSource) Type() string {
	return C.ConvertorTypeRuleSetSource
}

func (s *RuleSetSource) ContentType(_ adapter.ConvertOptions) string {
	return "application/json"
}

func (s *RuleSetSource) From(ctx context.Context, content []byte, _ adapter.ConvertOptions) ([]adapter.Rule, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, E.New("source is not a JSON object")
	}
	options, err := json.UnmarshalExtendedContext[option.PlainRuleSetCompat](ctx, trimmed)
	if err != nil {
		return nil, err
	}
	return common.Map(options.Options.Rules, adapter.RuleFrom), nil
}

func (s *RuleSetSource) To(ctx context.Context, contentRules []adapter.Rule, options adapter.ConvertOptions) ([]byte, error) {
	ruleSet, err := buildRuleSet(ctx, contentRules, options)
	if err != nil {
		return nil, err
	}
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(ruleSet)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func Downgrade(source *option.PlainRuleSetCompat, version *semver.Version) {
	if source == nil || version == nil {
		return
	}
	if version.LessThan(ruleSetV1100) {
		source.Version = boxConstant.RuleSetVersion2
		source.Options.Rules = common.Filter(source.Options.Rules, filter1100Rule)
	}
	if version.LessThan(ruleSetV1000) {
		source.Version = boxConstant.RuleSetVersion1
	}
}

func filter1100Rule(it option.HeadlessRule) bool {
	return !hasRule([]option.HeadlessRule{it}, func(it option.DefaultHeadlessRule) bool {
		return len(it.NetworkType) > 0 || it.NetworkIsExpensive || it.NetworkIsConstrained
	})
}

func hasRule(rules []option.HeadlessRule, cond func(rule option.DefaultHeadlessRule) bool) bool {
	for _, rule := range rules {
		switch rule.Type {
		case boxConstant.RuleTypeDefault:
			if cond(rule.DefaultOptions) {
				return true
			}
		case boxConstant.RuleTypeLogical:
			if hasRule(rule.LogicalOptions.Rules, cond) {
				return true
			}
		}
	}
	return false
}

func buildRuleSet(ctx context.Context, contentRules []adapter.Rule, options adapter.ConvertOptions) (*option.PlainRuleSetCompat, error) {
	convertedRules, err := adapter.EmbedResourceRules(ctx, contentRules)
	if err != nil {
		return nil, err
	}
	isSingBox := options.Metadata.Platform == C.PlatformSingBox
	if isSingBox {
		convertedRules, err = asn.ConvertIPASNToIPCIDR(ctx, convertedRules)
		if err != nil {
			return nil, E.Cause(err, "convert IP-ASN to IP-CIDR")
		}
	}
	ruleSet := &option.PlainRuleSetCompat{
		Version: boxConstant.RuleSetVersionCurrent,
		Options: option.PlainRuleSet{
			Rules: common.Map(common.Filter(convertedRules, func(it adapter.Rule) bool {
				return it.Headlessable()
			}), adapter.Rule.ToHeadless),
		},
	}
	if isSingBox {
		Downgrade(ruleSet, options.Metadata.Version)
	}
	return ruleSet, nil
}
