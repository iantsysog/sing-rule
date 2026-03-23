package trie

// Adapted from https://github.com/openacid/succinct/blob/d4684c35d123f7528b14e03c24327231723db704/sskv.go

import (
	"sort"
	"strings"

	"github.com/iantsysog/sing-rule/convertor/internal/meta_utils"

	"github.com/openacid/low/bitmap"
)

const (
	complexWildcardByte = byte('+')
	wildcardByte        = byte('*')
	domainStepByte      = byte('.')
)

type DomainSet struct {
	leaves, labelBitmap []uint64
	labels              []byte
	ranks, selects      []int32
}

type qElt struct{ s, e, col int }

// NewDomainSet builds a DomainSet from a DomainTrie.
func (t *DomainTrie[T]) NewDomainSet() *DomainSet {
	if t == nil || t.root == nil {
		return nil
	}
	reserveDomains := make([]string, 0)
	t.Foreach(func(domain string, data T) bool {
		reserveDomains = append(reserveDomains, utils.Reverse(domain))
		return true
	})
	// Keep identical prefixes contiguous and ordered by lexicographic length progression.
	sort.Strings(reserveDomains)
	keys := reserveDomains
	if len(keys) == 0 {
		return nil
	}
	ss := &DomainSet{}
	lIdx := 0

	queue := []qElt{{0, len(keys), 0}}
	for i := 0; i < len(queue); i++ {
		elt := queue[i]
		if elt.col == len(keys[elt.s]) {
			elt.s++
			// Leaf node.
			setBit(&ss.leaves, i, 1)
		}

		for j := elt.s; j < elt.e; {

			frm := j

			for ; j < elt.e && keys[j][elt.col] == keys[frm][elt.col]; j++ {
			}
			queue = append(queue, qElt{frm, j, elt.col + 1})
			ss.labels = append(ss.labels, keys[frm][elt.col])
			setBit(&ss.labelBitmap, lIdx, 0)
			lIdx++
		}
		setBit(&ss.labelBitmap, lIdx, 1)
		lIdx++
	}

	ss.init()
	return ss
}

// Has reports whether key exists in the DomainSet.
func (ss *DomainSet) Has(key string) bool {
	if ss == nil || len(ss.labelBitmap) == 0 || len(ss.leaves) == 0 {
		return false
	}
	key = utils.Reverse(key)
	key = strings.ToLower(key)
	// Advance when no label matches at the current node.
	nodeId, bmIdx := 0, 0
	type wildcardCursor struct {
		bmIdx, index int
	}
	stack := make([]wildcardCursor, 0)
	for i := 0; i < len(key); i++ {
	RESTART:
		c := key[i]
		for ; ; bmIdx++ {
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				if len(stack) > 0 {
					cursor := stack[len(stack)-1]
					stack = stack[0 : len(stack)-1]
					// Backtrack wildcard and locate the next node.
					nextNodeId := countZeros(ss.labelBitmap, ss.ranks, cursor.bmIdx+1)
					nextBmIdx := selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nextNodeId-1) + 1
					j := cursor.index
					for ; j < len(key) && key[j] != domainStepByte; j++ {
					}
					if j == len(key) {
						if getBit(ss.leaves, nextNodeId) != 0 {
							return true
						} else {
							goto RESTART
						}
					}
					for ; nextBmIdx-nextNodeId < len(ss.labels); nextBmIdx++ {
						if ss.labels[nextBmIdx-nextNodeId] == domainStepByte {
							bmIdx = nextBmIdx
							nodeId = nextNodeId
							i = j
							goto RESTART
						}
					}
				}
				return false
			}
			// Handle domain wildcard labels.
			if ss.labels[bmIdx-nodeId] == complexWildcardByte {
				return true
			} else if ss.labels[bmIdx-nodeId] == wildcardByte {
				cursor := wildcardCursor{}
				cursor.bmIdx = bmIdx
				cursor.index = i
				stack = append(stack, cursor)
			} else if ss.labels[bmIdx-nodeId] == c {
				break
			}
		}
		nodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	return getBit(ss.leaves, nodeId) != 0
}

func (ss *DomainSet) keys(f func(key string) bool) {
	if ss == nil || f == nil || len(ss.labelBitmap) == 0 {
		return
	}
	var currentKey []byte
	var traverse func(int, int) bool
	traverse = func(nodeId, bmIdx int) bool {
		if getBit(ss.leaves, nodeId) != 0 {
			if !f(string(currentKey)) {
				return false
			}
		}

		for ; ; bmIdx++ {
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				return true
			}
			nextLabel := ss.labels[bmIdx-nodeId]
			currentKey = append(currentKey, nextLabel)
			nextNodeId := countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
			nextBmIdx := selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nextNodeId-1) + 1
			if !traverse(nextNodeId, nextBmIdx) {
				return false
			}
			currentKey = currentKey[:len(currentKey)-1]
		}
	}

	traverse(0, 0)
}

func (ss *DomainSet) Foreach(f func(key string) bool) {
	if ss == nil || f == nil {
		return
	}
	ss.keys(func(key string) bool {
		return f(utils.Reverse(key))
	})
}

// MatchDomain implements C.DomainMatcher.
func (ss *DomainSet) MatchDomain(domain string) bool {
	return ss.Has(domain)
}

func setBit(bm *[]uint64, i int, v int) {
	for i>>6 >= len(*bm) {
		*bm = append(*bm, 0)
	}
	(*bm)[i>>6] |= uint64(v) << uint(i&63)
}

func getBit(bm []uint64, i int) uint64 {
	if i < 0 || i>>6 >= len(bm) {
		return 0
	}
	return bm[i>>6] & (1 << uint(i&63))
}

// init builds precomputed indexes for rank and select.
func (ss *DomainSet) init() {
	if ss == nil {
		return
	}
	ss.selects, ss.ranks = bitmap.IndexSelect32R64(ss.labelBitmap)
}

// countZeros returns the number of zero bits before index i (excluding i), using rank indexes.
// Example:
//
//	countZeros("010010", 4) == 3
//	//          012345
func countZeros(bm []uint64, ranks []int32, i int) int {
	a, _ := bitmap.Rank64(bm, ranks, int32(i))
	return i - int(a)
}

// selectIthOne returns the bit index of the i-th one bit using rank and select indexes.
// Example:
//
//	selectIthOne("010010", 1) == 4
//	//            012345
func selectIthOne(bm []uint64, ranks, selects []int32, i int) int {
	a, _ := bitmap.Select32R64(bm, selects, ranks, int32(i))
	return int(a)
}
