package asn

import (
	"context"

	"github.com/iantsysog/sing-rule/adapter"
	"github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func ConvertIPASNToIPCIDR(ctx context.Context, rules []adapter.Rule) ([]adapter.Rule, error) {
	if len(rules) == 0 {
		return rules, nil
	}

	var resolver *ASNResolver
	err := walkRules(rules, func(rule *adapter.Rule) error {
		if rule.Type != constant.RuleTypeDefault {
			return nil
		}

		defaultRule := &rule.DefaultOptions
		if len(defaultRule.IPASN) == 0 && len(defaultRule.SourceIPASN) == 0 {
			return nil
		}

		if resolver == nil {
			newResolver, err := NewASNResolver()
			if err != nil {
				return E.Cause(err, "create ASN resolver")
			}
			resolver = newResolver
		}

		return convertDefaultRuleIPASN(ctx, resolver, defaultRule)
	})
	if err != nil {
		return nil, E.Cause(err, "convert rule IP-ASN")
	}

	return rules, nil
}

func convertDefaultRuleIPASN(ctx context.Context, resolver *ASNResolver, rule *adapter.DefaultRule) error {
	if err := resolveAndAppend(ctx, resolver, &rule.IPASN, &rule.IPCIDR); err != nil {
		return err
	}
	return resolveAndAppend(ctx, resolver, &rule.SourceIPASN, &rule.SourceIPCIDR)
}

func resolveAndAppend(ctx context.Context, resolver *ASNResolver, source *[]string, destination *badoption.Listable[string]) error {
	if len(*source) == 0 {
		return nil
	}

	prefixes, err := resolver.ResolveASNs(ctx, *source)
	if err != nil {
		return err
	}
	if len(prefixes) > 0 {
		*destination = append(*destination, prefixes...)
	}

	*source = nil
	return nil
}

func walkRules(rules []adapter.Rule, fn func(*adapter.Rule) error) error {
	if len(rules) == 0 {
		return nil
	}

	stack := make([]*adapter.Rule, 0, len(rules))
	for i := range rules {
		stack = append(stack, &rules[i])
	}

	for len(stack) > 0 {
		last := len(stack) - 1
		rule := stack[last]
		stack = stack[:last]

		if err := fn(rule); err != nil {
			return err
		}

		if rule.Type != constant.RuleTypeLogical {
			continue
		}
		for i := range rule.LogicalOptions.Rules {
			stack = append(stack, &rule.LogicalOptions.Rules[i])
		}
	}

	return nil
}
