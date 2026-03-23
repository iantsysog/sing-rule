package trie

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	wildcard        = "*"
	dotWildcard     = ""
	complexWildcard = "+"
	domainStep      = "."
)

// ErrInvalidDomain indicates an invalid domain input.
var ErrInvalidDomain = errors.New("invalid domain")

// DomainTrie stores and queries domain segments with wildcard support (for example, *.google.com).
type DomainTrie[T any] struct {
	root *Node[T]
}

func ValidAndSplitDomain(domain string) ([]string, bool) {
	if domain != "" && domain[len(domain)-1] == '.' {
		return nil, false
	}
	if domain != "" {
		if r, _ := utf8.DecodeRuneInString(domain); unicode.IsSpace(r) {
			return nil, false
		}
		if r, _ := utf8.DecodeLastRuneInString(domain); unicode.IsSpace(r) {
			return nil, false
		}
	}
	domain = strings.ToLower(domain)
	parts := strings.Split(domain, domainStep)
	if len(parts) == 1 {
		if parts[0] == "" {
			return nil, false
		}

		return parts, true
	}

	for _, part := range parts[1:] {
		if part == "" {
			return nil, false
		}
	}

	return parts, true
}

// Insert adds a domain rule.
// Supported forms:
// 1. www.example.com
// 2. *.example.com
// 3. subdomain.*.example.com
// 4. .example.com
// 5. +.example.com
func (t *DomainTrie[T]) Insert(domain string, data T) error {
	if t == nil || t.root == nil {
		return ErrInvalidDomain
	}
	parts, valid := ValidAndSplitDomain(domain)
	if !valid {
		return ErrInvalidDomain
	}

	if parts[0] == complexWildcard {
		t.insert(parts[1:], data)
		parts[0] = dotWildcard
		t.insert(parts, data)
	} else {
		t.insert(parts, data)
	}

	return nil
}

func (t *DomainTrie[T]) insert(parts []string, data T) {
	if t == nil || t.root == nil {
		return
	}
	node := t.root
	// Store domain labels in reverse order to reduce trie depth.
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		node = node.getOrNewChild(part)
	}

	node.setData(data)
}

// Search matches a domain using this priority:
// 1. exact label
// 2. wildcard label
// 3. dot wildcard label
func (t *DomainTrie[T]) Search(domain string) *Node[T] {
	if t == nil || t.root == nil {
		return nil
	}
	parts, valid := ValidAndSplitDomain(domain)
	if !valid || parts[0] == "" {
		return nil
	}

	n := t.search(t.root, parts)

	if n.isEmpty() {
		return nil
	}

	return n
}

func (t *DomainTrie[T]) search(node *Node[T], parts []string) *Node[T] {
	if node == nil {
		return nil
	}
	if len(parts) == 0 {
		return node
	}

	if c := node.getChild(parts[len(parts)-1]); c != nil {
		if n := t.search(c, parts[:len(parts)-1]); !n.isEmpty() {
			return n
		}
	}

	if c := node.getChild(wildcard); c != nil {
		if n := t.search(c, parts[:len(parts)-1]); !n.isEmpty() {
			return n
		}
	}

	return node.getChild(dotWildcard)
}

func (t *DomainTrie[T]) Optimize() {
	if t == nil || t.root == nil {
		return
	}
	t.root.optimize()
}

func (t *DomainTrie[T]) Foreach(fn func(domain string, data T) bool) {
	if t == nil || t.root == nil || fn == nil {
		return
	}
	for key, data := range t.root.getChildren() {
		recursion([]string{key}, data, fn)
		if !data.isEmpty() {
			if !fn(joinDomain([]string{key}), data.data) {
				return
			}
		}
	}
}

func (t *DomainTrie[T]) IsEmpty() bool {
	if t == nil || t.root == nil {
		return true
	}
	return len(t.root.getChildren()) == 0
}

func recursion[T any](items []string, node *Node[T], fn func(domain string, data T) bool) bool {
	if node == nil {
		return true
	}
	for key, data := range node.getChildren() {
		newItems := make([]string, 0, len(items)+1)
		newItems = append(newItems, key)
		newItems = append(newItems, items...)
		if !data.isEmpty() {
			domain := joinDomain(newItems)
			if domain[0] == domainStepByte {
				domain = complexWildcard + domain
			}
			if !fn(domain, data.Data()) {
				return false
			}
		}
		if !recursion(newItems, data, fn) {
			return false
		}
	}
	return true
}

func joinDomain(items []string) string {
	return strings.Join(items, domainStep)
}

// New returns an empty DomainTrie.
func New[T any]() *DomainTrie[T] {
	return &DomainTrie[T]{root: newNode[T]()}
}
