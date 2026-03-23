package adapter

import (
	boxConstant "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/ranges"
)

type Rule struct {
	Type           string
	DefaultOptions DefaultRule
	LogicalOptions LogicalRule
}

func RuleFrom(rule boxOption.HeadlessRule) Rule {
	return Rule{
		Type:           rule.Type,
		DefaultOptions: DefaultRuleFrom(rule.DefaultOptions),
		LogicalOptions: LogicalRuleFrom(rule.LogicalOptions),
	}
}

func (r Rule) Headlessable() bool {
	switch r.Type {
	case boxConstant.RuleTypeDefault:
		return r.DefaultOptions.Headlessable()
	case boxConstant.RuleTypeLogical:
		return r.LogicalOptions.Headlessable()
	default:
		return false
	}
}

func (r Rule) ToHeadless() boxOption.HeadlessRule {
	switch r.Type {
	case boxConstant.RuleTypeDefault:
		return boxOption.HeadlessRule{
			Type:           boxConstant.RuleTypeDefault,
			DefaultOptions: r.DefaultOptions.ToHeadless(),
		}
	case boxConstant.RuleTypeLogical:
		return boxOption.HeadlessRule{
			Type:           boxConstant.RuleTypeLogical,
			LogicalOptions: r.LogicalOptions.ToHeadless(),
		}
	default:
		return boxOption.HeadlessRule{}
	}
}

type DefaultRule struct {
	boxOption.DefaultHeadlessRule

	GEOIP       []string
	SourceGEOIP []string
	IPASN       []string
	SourceIPASN []string
	GEOSite     []string

	Inbound     []string
	InboundType []string
	InboundPort []ranges.Range[uint16]
	InboundUser []string
}

func DefaultRuleFrom(rule boxOption.DefaultHeadlessRule) DefaultRule {
	return DefaultRule{
		DefaultHeadlessRule: rule,
	}
}

func (r DefaultRule) Headlessable() bool {
	return len(r.GEOIP) == 0 && len(r.SourceGEOIP) == 0 &&
		len(r.IPASN) == 0 && len(r.SourceIPASN) == 0 &&
		len(r.Inbound) == 0 && len(r.InboundType) == 0 && len(r.InboundPort) == 0 && len(r.InboundUser) == 0
}

func (r DefaultRule) ToHeadless() boxOption.DefaultHeadlessRule {
	return r.DefaultHeadlessRule
}

type LogicalRule struct {
	Mode   string
	Rules  []Rule
	Invert bool
}

func LogicalRuleFrom(rule boxOption.LogicalHeadlessRule) LogicalRule {
	return LogicalRule{
		Mode:   rule.Mode,
		Rules:  common.Map(rule.Rules, RuleFrom),
		Invert: rule.Invert,
	}
}

func (r LogicalRule) Headlessable() bool {
	return common.All(r.Rules, Rule.Headlessable)
}

func (r LogicalRule) ToHeadless() boxOption.LogicalHeadlessRule {
	return boxOption.LogicalHeadlessRule{
		Mode:   r.Mode,
		Rules:  common.Map(r.Rules, Rule.ToHeadless),
		Invert: r.Invert,
	}
}
