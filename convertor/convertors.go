package convertor

import (
	"github.com/iantsysog/sing-rule/adapter"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/convertor/adguard"
	"github.com/iantsysog/sing-rule/convertor/clash"
)

var Convertors = map[string]adapter.Convertor{
	C.ConvertorTypeRuleSetSource:     &RuleSetSource{},
	C.ConvertorTypeRuleSetBinary:     &RuleSetBinary{},
	C.ConvertorTypeAdGuardRuleSet:    &adguard.RuleSet{},
	C.ConvertorTypeClashRuleProvider: &clash.RuleProvider{},
	C.ConvertorTypeSurgeRuleSet:      &SurgeRuleSet{},
}
