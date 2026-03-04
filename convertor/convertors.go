package convertor

import (
	"github.com/iantsysog/sing-rule/adapter"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/convertor/adguard"
	"github.com/iantsysog/sing-rule/convertor/clash"
)

var Convertors = map[string]adapter.Convertor{
	C.ConvertorTypeRuleSetSource:     (*RuleSetSource)(nil),
	C.ConvertorTypeRuleSetBinary:     (*RuleSetBinary)(nil),
	C.ConvertorTypeAdGuardRuleSet:    (*adguard.RuleSet)(nil),
	C.ConvertorTypeClashRuleProvider: (*clash.RuleProvider)(nil),
	C.ConvertorTypeSurgeRuleSet:      (*SurgeRuleSet)(nil),
}
