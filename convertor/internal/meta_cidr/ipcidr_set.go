package cidr

import (
	"fmt"
	"net/netip"
	"unsafe"

	"go4.org/netipx"
)

type IpCidrSet struct {
	// Must match netipx.IPSet layout.
	rr []netipx.IPRange
}

func NewIpCidrSet() *IpCidrSet {
	return &IpCidrSet{}
}

func (set *IpCidrSet) AddIpCidrForString(ipCidr string) error {
	prefix, err := netip.ParsePrefix(ipCidr)
	if err != nil {
		return err
	}
	return set.AddIpCidr(prefix)
}

func (set *IpCidrSet) AddIpCidr(ipCidr netip.Prefix) (err error) {
	if r := netipx.RangeOfPrefix(ipCidr); r.IsValid() {
		set.rr = append(set.rr, r)
	} else {
		err = fmt.Errorf("not valid ipcidr range: %s", ipCidr)
	}
	return
}

func (set *IpCidrSet) IsContainForString(ipString string) bool {
	ip, err := netip.ParseAddr(ipString)
	if err != nil {
		return false
	}
	return set.IsContain(ip)
}

func (set *IpCidrSet) IsContain(ip netip.Addr) bool {
	if set == nil {
		return false
	}
	return set.ToIPSet().Contains(ip.WithZone(""))
}

// MatchIp implements C.IpMatcher.
func (set *IpCidrSet) MatchIp(ip netip.Addr) bool {
	if set.IsEmpty() {
		return false
	}
	return set.IsContain(ip)
}

func (set *IpCidrSet) Merge() error {
	if set == nil || len(set.rr) == 0 {
		return nil
	}
	var b netipx.IPSetBuilder
	b.AddSet(set.ToIPSet())
	i, err := b.IPSet()
	if err != nil {
		return err
	}
	set.fromIPSet(i)
	return nil
}

func (set *IpCidrSet) IsEmpty() bool {
	return set == nil || len(set.rr) == 0
}

func (set *IpCidrSet) Foreach(f func(prefix netip.Prefix) bool) {
	if set == nil || f == nil {
		return
	}
	for _, r := range set.rr {
		for _, prefix := range r.Prefixes() {
			if !f(prefix) {
				return
			}
		}
	}
}

// ToIPSet performs an unsafe conversion to *netipx.IPSet.
// Call Merge before using it.
func (set *IpCidrSet) ToIPSet() *netipx.IPSet {
	if set == nil {
		return nil
	}
	return (*netipx.IPSet)(unsafe.Pointer(set))
}

func (set *IpCidrSet) fromIPSet(i *netipx.IPSet) {
	if set == nil || i == nil {
		return
	}
	*set = *(*IpCidrSet)(unsafe.Pointer(i))
}
