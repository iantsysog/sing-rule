package trie

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const domainSetBinaryVersion = 1

var errInvalidDomainSetVersion = errors.New("invalid domain set binary version")
var errInvalidDomainSetLength = errors.New("invalid domain set binary length")

func (ss *DomainSet) WriteBin(w io.Writer) (err error) {
	if ss == nil {
		return errors.New("nil domain set")
	}
	// Version.
	_, err = w.Write([]byte{domainSetBinaryVersion})
	if err != nil {
		return err
	}

	// Leaves.
	err = binary.Write(w, binary.BigEndian, int64(len(ss.leaves)))
	if err != nil {
		return err
	}
	for _, d := range ss.leaves {
		err = binary.Write(w, binary.BigEndian, d)
		if err != nil {
			return err
		}
	}

	// Label bitmap.
	err = binary.Write(w, binary.BigEndian, int64(len(ss.labelBitmap)))
	if err != nil {
		return err
	}
	for _, d := range ss.labelBitmap {
		err = binary.Write(w, binary.BigEndian, d)
		if err != nil {
			return err
		}
	}

	// Labels.
	err = binary.Write(w, binary.BigEndian, int64(len(ss.labels)))
	if err != nil {
		return err
	}
	_, err = w.Write(ss.labels)
	if err != nil {
		return err
	}

	return nil
}

func ReadDomainSetBin(r io.Reader) (ds *DomainSet, err error) {
	// Version.
	version := make([]byte, 1)
	_, err = io.ReadFull(r, version)
	if err != nil {
		return nil, err
	}
	if version[0] != domainSetBinaryVersion {
		return nil, errInvalidDomainSetVersion
	}

	ds = &DomainSet{}
	var length int64

	// Leaves.
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 0 || length > math.MaxInt32 {
		return nil, errInvalidDomainSetLength
	}
	if length == 0 {
		return nil, fmt.Errorf("%w: leaves", errInvalidDomainSetLength)
	}
	ds.leaves = make([]uint64, length)
	for i := int64(0); i < length; i++ {
		err = binary.Read(r, binary.BigEndian, &ds.leaves[i])
		if err != nil {
			return nil, err
		}
	}

	// Label bitmap.
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 0 || length > math.MaxInt32 {
		return nil, errInvalidDomainSetLength
	}
	if length == 0 {
		return nil, fmt.Errorf("%w: labelBitmap", errInvalidDomainSetLength)
	}
	ds.labelBitmap = make([]uint64, length)
	for i := int64(0); i < length; i++ {
		err = binary.Read(r, binary.BigEndian, &ds.labelBitmap[i])
		if err != nil {
			return nil, err
		}
	}

	// Labels.
	err = binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length < 0 || length > math.MaxInt32 {
		return nil, errInvalidDomainSetLength
	}
	if length == 0 {
		return nil, fmt.Errorf("%w: labels", errInvalidDomainSetLength)
	}
	ds.labels = make([]byte, length)
	_, err = io.ReadFull(r, ds.labels)
	if err != nil {
		return nil, err
	}

	ds.init()
	return ds, nil
}
