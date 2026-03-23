package constant

type ConvertorType = string

const (
	ConvertorTypeRuleSetSource     ConvertorType = "source"
	ConvertorTypeRuleSetBinary     ConvertorType = "binary"
	ConvertorTypeAdGuardRuleSet    ConvertorType = "adguard"
	ConvertorTypeClashRuleProvider ConvertorType = "clash"
	ConvertorTypeSurgeRuleSet      ConvertorType = "surge"
)
