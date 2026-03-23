package cache

import (
	"slices"
	"time"

	"github.com/iantsysog/sing-rule/adapter"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
)

var _ adapter.Cache = (*MemoryCache)(nil)

type MemoryCache struct {
	freelru.Cache[string, *adapter.SavedBinary]
}

func NewMemory(expiration time.Duration) *MemoryCache {
	cache := common.Must1(freelru.NewSharded[string, *adapter.SavedBinary](1024, maphash.NewHasher[string]().Hash32))
	cache.SetLifetime(expiration)
	return &MemoryCache{
		Cache: cache,
	}
}

func (c *MemoryCache) Start() error {
	return nil
}

func (c *MemoryCache) Close() error {
	return nil
}

func (c *MemoryCache) LoadBinary(tag string) (*adapter.SavedBinary, error) {
	savedBinary, loaded := c.Get(tag)
	if !loaded {
		return nil, nil
	}
	return cloneSavedBinary(savedBinary), nil
}

func (c *MemoryCache) SaveBinary(tag string, binary *adapter.SavedBinary) error {
	if binary == nil {
		c.Remove(tag)
		return nil
	}
	c.Add(tag, cloneSavedBinary(binary))
	return nil
}

func cloneSavedBinary(binary *adapter.SavedBinary) *adapter.SavedBinary {
	if binary == nil {
		return nil
	}
	return &adapter.SavedBinary{
		Content:     slices.Clone(binary.Content),
		LastUpdated: binary.LastUpdated,
		LastEtag:    binary.LastEtag,
	}
}
