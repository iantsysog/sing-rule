package clash

import (
	"bytes"
	"context"
	"strings"

	"github.com/iantsysog/sing-rule/adapter"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/convertor/internal/lineparse"
	boxConstant "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"

	"sigs.k8s.io/yaml"
)

var _ adapter.Convertor = (*RuleProvider)(nil)

type RuleProvider struct{}

func (c *RuleProvider) Type() string {
	return C.ConvertorTypeClashRuleProvider
}

func (c *RuleProvider) ContentType(options adapter.ConvertOptions) string {
	switch options.Options.TargetConvertOptions.ClashOptions.TargetFormat {
	case "yaml":
		return "application/x-yaml"
	case "mrs":
		return "application/octet-stream"
	default:
		return "text/plain"
	}
}

func (c *RuleProvider) From(ctx context.Context, content []byte, options adapter.ConvertOptions) ([]adapter.Rule, error) {
	format := options.Options.SourceConvertOptions.ClashOptions.SourceFormat
	lines, useTextScanner, err := parseSourceLines(format, content)
	if err != nil {
		return nil, err
	}
	switch format {
	case "mrs":
		return fromMrs(content)
	}
	behavior := options.Options.SourceConvertOptions.ClashOptions.SourceBehavior
	switch behavior {
	case "domain":
		var rule adapter.DefaultRule
		if !useTextScanner {
			for _, line := range lines {
				fromDomainLine(&rule, line)
			}
		} else {
			err := lineparse.ForEach(content, func(line string) error {
				fromDomainLine(&rule, line)
				return nil
			}, "#")
			if err != nil {
				return nil, E.Cause(err, "scan domain rules")
			}
		}
		return []adapter.Rule{{Type: boxConstant.RuleTypeDefault, DefaultOptions: rule}}, nil
	case "ipcidr":
		var rule adapter.DefaultRule
		if !useTextScanner {
			for _, line := range lines {
				fromIPCIDRLine(&rule, line)
			}
		} else {
			err := lineparse.ForEach(content, func(line string) error {
				fromIPCIDRLine(&rule, line)
				return nil
			}, "#")
			if err != nil {
				return nil, E.Cause(err, "scan ipcidr rules")
			}
		}
		return []adapter.Rule{{Type: boxConstant.RuleTypeDefault, DefaultOptions: rule}}, nil
	case "classical":
		var rules []adapter.Rule
		if !useTextScanner {
			for _, line := range lines {
				rule, err := fromClassicalLine(line)
				if err != nil {
					continue
				}
				if rule != nil {
					rules = append(rules, *rule)
				}
			}
		} else {
			err := lineparse.ForEach(content, func(line string) error {
				rule, err := fromClassicalLine(line)
				if err != nil {
					return nil
				}
				if rule != nil {
					rules = append(rules, *rule)
				}
				return nil
			}, "#")
			if err != nil {
				return nil, E.Cause(err, "scan classical rules")
			}
		}
		return adapter.MergeRules(rules), nil
	case "":
		return nil, E.New("missing source behavior in options")
	default:
		return nil, E.New("unknown source behavior: ", behavior)
	}
}

func (c *RuleProvider) To(ctx context.Context, contentRules []adapter.Rule, options adapter.ConvertOptions) ([]byte, error) {
	convertedRules, err := adapter.EmbedResourceRules(ctx, contentRules)
	if err != nil {
		return nil, err
	}
	format := options.Options.TargetConvertOptions.ClashOptions.TargetFormat
	behavior := options.Options.TargetConvertOptions.ClashOptions.TargetBehavior
	if format == "mrs" {
		return toMrs(behavior, convertedRules)
	}
	ruleLines, err := toLines(behavior, convertedRules)
	if err != nil {
		return nil, err
	}
	switch format {
	case "text":
		var output bytes.Buffer
		for _, line := range ruleLines {
			output.WriteString(line)
			output.WriteByte('\n')
		}
		return output.Bytes(), nil
	case "yaml":
		ruleProvider := struct {
			Payload []string `yaml:"payload"`
		}{
			Payload: ruleLines,
		}
		marshaled, err := yaml.Marshal(ruleProvider)
		if err != nil {
			return nil, err
		}
		return marshaled, nil
	case "":
		return nil, E.New("missing target format in options")
	default:
		return nil, E.New("unknown target format: ", format)
	}
}

func fromDomainLine(rule *adapter.DefaultRule, ruleLine string) {
	ruleLine = strings.TrimSpace(ruleLine)
	if ruleLine == "" || strings.HasPrefix(ruleLine, "#") {
		return
	}
	var domainSuffix bool
	if strings.HasPrefix(ruleLine, "+.") {
		domainSuffix = true
		ruleLine = strings.TrimPrefix(ruleLine, "+.")
	}
	if strings.Contains(ruleLine, "+") || strings.Contains(ruleLine, "*") {
		return
	}
	if domainSuffix {
		rule.DomainSuffix = append(rule.DomainSuffix, ruleLine)
	} else {
		rule.Domain = append(rule.Domain, ruleLine)
	}
}

func fromIPCIDRLine(rule *adapter.DefaultRule, ruleLine string) {
	ruleLine = strings.TrimSpace(ruleLine)
	if ruleLine == "" || strings.HasPrefix(ruleLine, "#") {
		return
	}
	rule.IPCIDR = append(rule.IPCIDR, ruleLine)
}

func toLines(behavior string, rules []adapter.Rule) ([]string, error) {
	var lines []string
	switch behavior {
	case "domain":
		for _, rule := range rules {
			if rule.Type != boxConstant.RuleTypeDefault || !adapter.IsDestinationAddressRule(rule.DefaultOptions) {
				continue
			}
			for _, domain := range rule.DefaultOptions.Domain {
				lines = append(lines, domain)
			}
			for _, domainSuffix := range rule.DefaultOptions.DomainSuffix {
				lines = append(lines, "+."+domainSuffix)
			}
		}
		return lines, nil
	case "ipcidr":
		for _, rule := range rules {
			if rule.Type != boxConstant.RuleTypeDefault || !adapter.IsDestinationAddressRule(rule.DefaultOptions) {
				continue
			}
			for _, ipCidr := range rule.DefaultOptions.IPCIDR {
				lines = append(lines, ipCidr)
			}
		}
	case "classical":
		for _, rule := range rules {
			ruleLines, err := toClassicalLine(rule)
			if err != nil {
				return nil, err
			}
			lines = append(lines, ruleLines...)
		}
		return lines, nil
	}
	return nil, E.New("unknown target behavior: ", behavior)
}

func parseSourceLines(format string, content []byte) ([]string, bool, error) {
	switch format {
	case "text":
		return nil, true, nil
	case "yaml":
		var ruleProvider struct {
			Payload []string `yaml:"payload"`
		}
		if err := yaml.Unmarshal(content, &ruleProvider); err != nil {
			return nil, false, err
		}
		return ruleProvider.Payload, false, nil
	case "mrs":
		return nil, false, nil
	case "":
		return nil, false, E.New("missing source format in options")
	default:
		return nil, false, E.New("unknown source format: ", format)
	}
}

func IsSimpleDomainRule(rule adapter.DefaultRule) bool {
	return len(rule.DomainKeyword) == 0 &&
		len(rule.DomainRegex) == 0 &&
		len(rule.SourceIPCIDR) == 0 &&
		len(rule.IPCIDR) == 0 &&
		len(rule.SourcePort) == 0 &&
		len(rule.SourcePortRange) == 0 &&
		len(rule.Port) == 0 &&
		len(rule.PortRange) == 0 &&
		len(rule.ProcessName) == 0 &&
		len(rule.ProcessPath) == 0 &&
		len(rule.ProcessPathRegex) == 0 &&
		len(rule.PackageName) == 0 &&
		len(rule.Network) == 0 &&
		len(rule.QueryType) == 0 &&
		len(rule.NetworkType) == 0 &&
		!rule.NetworkIsExpensive &&
		!rule.NetworkIsConstrained &&
		len(rule.WIFISSID) == 0 &&
		len(rule.WIFIBSSID) == 0 &&
		len(rule.GEOIP) == 0 &&
		len(rule.SourceGEOIP) == 0 &&
		len(rule.IPASN) == 0 &&
		len(rule.SourceIPASN) == 0 &&
		len(rule.GEOSite) == 0 &&
		len(rule.Inbound) == 0 &&
		len(rule.InboundType) == 0 &&
		len(rule.InboundPort) == 0 &&
		len(rule.InboundUser) == 0 &&
		!rule.Invert &&
		len(rule.AdGuardDomain) == 0 &&
		rule.AdGuardDomainMatcher == nil &&
		rule.DomainMatcher == nil &&
		rule.SourceIPSet == nil &&
		rule.IPSet == nil &&
		rule.NetworkInterfaceAddress == nil &&
		len(rule.DefaultInterfaceAddress) == 0
}
