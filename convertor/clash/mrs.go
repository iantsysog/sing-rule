package clash

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"sort"
	"strings"

	"github.com/iantsysog/sing-rule/adapter"
	"github.com/iantsysog/sing-rule/convertor/internal/meta_cidr"
	"github.com/iantsysog/sing-rule/convertor/internal/meta_domainset"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"

	"github.com/klauspost/compress/zstd"
	"slices"
)

var MrsMagicBytes = [4]byte{'M', 'R', 'S', 1} // MRSv1

func fromMrs(content []byte) ([]adapter.Rule, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	var header [4]byte
	_, err = io.ReadFull(decoder, header[:])
	if err != nil {
		return nil, err
	}
	if header != MrsMagicBytes {
		return nil, E.New("invalid MrsMagic bytes")
	}
	var behavior byte
	err = binary.Read(decoder, binary.BigEndian, &behavior)
	if err != nil {
		return nil, err
	}
	var length int64
	err = binary.Read(decoder, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, E.New("invalid reserved length: ", length)
	} else if length > 0 {
		err = rw.SkipN(decoder, int(length))
		if err != nil {
			return nil, E.Cause(err, "discard reserved bytes")
		}
	}
	switch behavior {
	case 0:
		var domainSet *trie.DomainSet
		domainSet, err = trie.ReadDomainSetBin(decoder)
		if err != nil {
			return nil, err
		}
		var keys []string
		domainSet.Foreach(func(key string) bool {
			keys = append(keys, key)
			return true
		})
		sort.Strings(keys)
		var rule adapter.DefaultRule
		for _, key := range keys {
			if _, ok := slices.BinarySearch(keys, "+."+key); ok {
				continue
			}
			if after, ok := strings.CutPrefix(key, "+."); ok {
				rule.DomainSuffix = append(rule.DomainSuffix, after)
			} else {
				if strings.Contains(key, "+") || strings.Contains(key, "*") {
					continue
				}
				rule.Domain = append(rule.Domain, key)
			}
		}
		return []adapter.Rule{{Type: C.RuleTypeDefault, DefaultOptions: rule}}, nil
	case 1:
		var ipCidrSet *cidr.IpCidrSet
		ipCidrSet, err = cidr.ReadIpCidrSet(decoder)
		if err != nil {
			return nil, err
		}
		return []adapter.Rule{{
			Type: C.RuleTypeDefault,
			DefaultOptions: adapter.DefaultRule{
				DefaultHeadlessRule: option.DefaultHeadlessRule{
					IPCIDR: common.Map(ipCidrSet.ToIPSet().Prefixes(), netip.Prefix.String),
				},
			},
		}}, nil
	default:
		return nil, E.New("invalid behavior: ", behavior)
	}
}

func toMrs(behavior string, rules []adapter.Rule) ([]byte, error) {
	var output bytes.Buffer
	encoder, err := zstd.NewWriter(&output, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return nil, err
	}
	_, err = encoder.Write(MrsMagicBytes[:])
	if err != nil {
		return nil, err
	}
	var behaviorByte byte
	switch behavior {
	case "domain":
		behaviorByte = 0
	case "ipcidr":
		behaviorByte = 1
	default:
		return nil, E.New("invalid behavior: ", behavior)
	}
	var ruleSize int64
	for _, rule := range rules {
		if rule.Type != C.RuleTypeDefault || !adapter.IsDestinationAddressRule(rule.DefaultOptions) {
			continue
		}
		if behaviorByte == 0 {
			ruleSize += int64(len(rule.DefaultOptions.Domain) + len(rule.DefaultOptions.DomainSuffix))
		} else {
			ruleSize += int64(len(rule.DefaultOptions.IPCIDR))
		}
	}
	if _, err = encoder.Write([]byte{behaviorByte}); err != nil {
		return nil, err
	}
	err = binary.Write(encoder, binary.BigEndian, ruleSize)
	if err != nil {
		return nil, err
	}
	err = binary.Write(encoder, binary.BigEndian, int64(0))
	if err != nil {
		return nil, err
	}
	domainTrie := trie.New[struct{}]()
	ipCidrTrie := cidr.NewIpCidrSet()
	for _, rule := range rules {
		if rule.Type != C.RuleTypeDefault || !adapter.IsDestinationAddressRule(rule.DefaultOptions) {
			continue
		}
		if behaviorByte == 0 {
			for _, domain := range rule.DefaultOptions.Domain {
				domainTrie.Insert(domain, struct{}{})
			}
			for _, domainSuffix := range rule.DefaultOptions.DomainSuffix {
				domainTrie.Insert("+."+domainSuffix, struct{}{})
			}
		} else {
			for _, ipCidr := range rule.DefaultOptions.IPCIDR {
				if err = ipCidrTrie.AddIpCidrForString(ipCidr); err != nil {
					return nil, E.Cause(err, "invalid ipcidr: ", ipCidr)
				}
			}
		}
	}
	if behaviorByte == 0 {
		domainSet := domainTrie.NewDomainSet()
		if domainSet == nil {
			return []byte{}, nil
		}
		err = domainSet.WriteBin(encoder)
		if err != nil {
			return nil, E.Cause(err, "compile mrs")
		}
	} else {
		err = ipCidrTrie.WriteBin(encoder)
		if err != nil {
			return nil, E.Cause(err, "compile mrs")
		}
	}
	err = encoder.Close()
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
