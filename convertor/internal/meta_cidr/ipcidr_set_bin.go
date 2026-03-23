package cidr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"

	"go4.org/netipx"
)

const ipCidrSetBinaryVersion = 1

var errInvalidBinaryVersion = errors.New("invalid ipcidr set binary version")
var errInvalidRangeLength = errors.New("invalid ipcidr set range length")

func (ss *IpCidrSet) WriteBin(w io.Writer) (err error) {
	if ss == nil {
		return errors.New("nil ipcidr set")
	}
	// Version.
	if _, err = w.Write([]byte{ipCidrSetBinaryVersion}); err != nil {
		return err
	}

	// Ranges.
	if err = binary.Write(w, binary.BigEndian, int64(len(ss.rr))); err != nil {
		return err
	}
	for _, r := range ss.rr {
		if !r.IsValid() {
			return fmt.Errorf("invalid ip range: %v", r)
		}
		if err = binary.Write(w, binary.BigEndian, r.From().As16()); err != nil {
			return err
		}
		if err = binary.Write(w, binary.BigEndian, r.To().As16()); err != nil {
			return err
		}
	}

	return nil
}

func ReadIpCidrSet(r io.Reader) (ss *IpCidrSet, err error) {
	// Version.
	version := make([]byte, 1)
	_, err = io.ReadFull(r, version)
	if err != nil {
		return nil, err
	}
	if version[0] != ipCidrSetBinaryVersion {
		return nil, errInvalidBinaryVersion
	}

	ss = NewIpCidrSet()
	var length int64

	// Ranges.
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 0 || length > math.MaxInt32 {
		return nil, errInvalidRangeLength
	}
	if length == 0 {
		return ss, nil
	}
	ss.rr = make([]netipx.IPRange, length)
	for i := int64(0); i < length; i++ {
		var a16 [16]byte
		err = binary.Read(r, binary.BigEndian, &a16)
		if err != nil {
			return nil, err
		}
		from := netip.AddrFrom16(a16).Unmap()
		err = binary.Read(r, binary.BigEndian, &a16)
		if err != nil {
			return nil, err
		}
		to := netip.AddrFrom16(a16).Unmap()
		ipRange := netipx.IPRangeFrom(from, to)
		if !ipRange.IsValid() {
			return nil, fmt.Errorf("invalid ip range from %s to %s", from, to)
		}
		ss.rr[i] = ipRange
	}

	return ss, nil
}
