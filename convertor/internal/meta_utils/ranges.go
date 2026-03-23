package utils

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type signedInteger interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type unsignedInteger interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

type integer interface {
	signedInteger | unsignedInteger
}

type IntRanges[T integer] []Range[T]

var errIntRanges = errors.New("intRanges error")

func newIntRanges[T integer](expected string, parseFn func(string) (T, error)) (IntRanges[T], error) {
	expected = strings.TrimSpace(expected)
	if expected == "" || expected == "*" {
		return nil, nil
	}
	expected = strings.ReplaceAll(expected, ",", "/")
	list := strings.Split(expected, "/")
	if len(list) > 28 {
		return nil, fmt.Errorf("%w, too many ranges to use, maximum support 28 ranges", errIntRanges)
	}
	return newIntRangesFromList(list, parseFn)
}

func newIntRangesFromList[T integer](list []string, parseFn func(string) (T, error)) (IntRanges[T], error) {
	ranges := make(IntRanges[T], 0, len(list))
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		startPart, endPart, hasRange := strings.Cut(item, "-")
		start, err := parseFn(strings.Trim(startPart, "[] "))
		if err != nil {
			return nil, errIntRanges
		}
		if !hasRange {
			ranges = append(ranges, NewRange(start, start))
			continue
		}
		if strings.Contains(endPart, "-") {
			return nil, errIntRanges
		}
		end, err := parseFn(strings.Trim(endPart, "[] "))
		if err != nil {
			return nil, errIntRanges
		}
		ranges = append(ranges, NewRange(start, end))
	}
	return ranges, nil
}

func parseUnsigned[T unsignedInteger](s string) (T, error) {
	value, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	typed := T(value)
	if uint64(typed) != value {
		return 0, errIntRanges
	}
	return typed, nil
}

func NewUnsignedRanges[T unsignedInteger](expected string) (IntRanges[T], error) {
	return newIntRanges(expected, parseUnsigned[T])
}

func NewUnsignedRangesFromList[T unsignedInteger](list []string) (IntRanges[T], error) {
	return newIntRangesFromList(list, parseUnsigned[T])
}

func parseSigned[T signedInteger](s string) (T, error) {
	value, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	typed := T(value)
	if int64(typed) != value {
		return 0, errIntRanges
	}
	return typed, nil
}

func NewSignedRanges[T signedInteger](expected string) (IntRanges[T], error) {
	return newIntRanges(expected, parseSigned[T])
}

func NewSignedRangesFromList[T signedInteger](list []string) (IntRanges[T], error) {
	return newIntRangesFromList(list, parseSigned[T])
}

func (ranges IntRanges[T]) Check(status T) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, segment := range ranges {
		if segment.Contains(status) {
			return true
		}
	}
	return false
}

func (ranges IntRanges[T]) String() string {
	if len(ranges) == 0 {
		return "*"
	}
	terms := make([]string, len(ranges))
	for i, r := range ranges {
		start := r.Start()
		end := r.End()
		if start == end {
			terms[i] = fmt.Sprint(start)
		} else {
			terms[i] = fmt.Sprint(start, "-", end)
		}
	}
	return strings.Join(terms, "/")
}

func (ranges IntRanges[T]) Range(f func(t T) bool) {
	for _, r := range ranges {
		for i := r.Start(); i <= r.End() && i >= r.Start(); i++ {
			if !f(i) {
				return
			}
			if i+1 < i {
				break
			}
		}
	}
}

func (ranges IntRanges[T]) Merge() (mergedRanges IntRanges[T]) {
	if len(ranges) == 0 {
		return nil
	}
	sorted := append(IntRanges[T](nil), ranges...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Start() < sorted[j].Start()
	})
	mergedRanges = sorted[:1]
	mergedIndex := 0
	for _, r := range sorted[1:] {
		end := mergedRanges[mergedIndex].End()
		next := end + 1
		if next > end && r.Start() > next {
			mergedRanges = append(mergedRanges, r)
			mergedIndex++
			continue
		}
		if r.End() > mergedRanges[mergedIndex].End() {
			mergedRanges[mergedIndex].end = r.End()
		}
	}
	return mergedRanges
}
