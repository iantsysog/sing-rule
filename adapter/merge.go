package adapter

import (
	C "github.com/sagernet/sing-box/constant"
)

func MergeRules(rules []Rule) []Rule {
	return mergeDestinationAddressRules(rules)
}

func mergeDestinationAddressRules(rules []Rule) []Rule {
	outputRules := make([]Rule, 0, len(rules))
	var destinationRule DefaultRule
	var hasDestinationRule bool
	for _, rule := range rules {
		if rule.Type == C.RuleTypeDefault && IsDestinationAddressRule(rule.DefaultOptions) {
			if !hasDestinationRule {
				destinationRule = rule.DefaultOptions
				hasDestinationRule = true
			} else {
				destinationRule.Domain = append(destinationRule.Domain, rule.DefaultOptions.Domain...)
				destinationRule.DomainSuffix = append(destinationRule.DomainSuffix, rule.DefaultOptions.DomainSuffix...)
				destinationRule.DomainKeyword = append(destinationRule.DomainKeyword, rule.DefaultOptions.DomainKeyword...)
				destinationRule.DomainRegex = append(destinationRule.DomainRegex, rule.DefaultOptions.DomainRegex...)
				destinationRule.IPCIDR = append(destinationRule.IPCIDR, rule.DefaultOptions.IPCIDR...)
				destinationRule.GEOIP = append(destinationRule.GEOIP, rule.DefaultOptions.GEOIP...)
				destinationRule.IPASN = append(destinationRule.IPASN, rule.DefaultOptions.IPASN...)
			}
		} else {
			outputRules = append(outputRules, rule)
		}
	}
	if hasDestinationRule {
		outputRules = append(outputRules, Rule{})
		copy(outputRules[1:], outputRules[:len(outputRules)-1])
		outputRules[0] = Rule{Type: C.RuleTypeDefault, DefaultOptions: destinationRule}
	}
	return outputRules
}

func IsDestinationAddressRule(rule DefaultRule) bool {
	return len(rule.QueryType) == 0 &&
		len(rule.Network) == 0 &&
		len(rule.SourceIPCIDR) == 0 &&
		len(rule.SourcePort) == 0 &&
		len(rule.SourcePortRange) == 0 &&
		len(rule.Port) == 0 &&
		len(rule.PortRange) == 0 &&
		len(rule.ProcessName) == 0 &&
		len(rule.ProcessPath) == 0 &&
		len(rule.ProcessPathRegex) == 0 &&
		len(rule.PackageName) == 0 &&
		len(rule.NetworkType) == 0 &&
		!rule.NetworkIsExpensive &&
		!rule.NetworkIsConstrained &&
		len(rule.WIFISSID) == 0 &&
		len(rule.WIFIBSSID) == 0 &&
		rule.NetworkInterfaceAddress == nil &&
		len(rule.DefaultInterfaceAddress) == 0 &&
		!rule.Invert &&
		rule.DomainMatcher == nil &&
		rule.SourceIPSet == nil &&
		rule.IPSet == nil &&
		len(rule.AdGuardDomain) == 0 &&
		rule.AdGuardDomainMatcher == nil &&
		len(rule.SourceGEOIP) == 0 &&
		len(rule.SourceIPASN) == 0 &&
		len(rule.GEOSite) == 0 &&
		len(rule.Inbound) == 0 &&
		len(rule.InboundType) == 0 &&
		len(rule.InboundPort) == 0 &&
		len(rule.InboundUser) == 0
}
