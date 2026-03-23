package option

import (
	"strings"
	"time"

	C "github.com/iantsysog/sing-rule/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

type _CacheOptions struct {
	Type         string            `json:"type,omitempty"`
	RedisOptions RedisCacheOptions `json:"-"`
	Expiration   time.Duration     `json:"expiration,omitempty"`
}

type CacheOptions _CacheOptions

func (o CacheOptions) MarshalJSON() ([]byte, error) {
	cacheType := strings.ToLower(strings.TrimSpace(o.Type))
	var v any
	switch cacheType {
	case "", C.CacheTypeMemory:
	case C.CacheTypeRedis:
		v = o.RedisOptions
	default:
		return nil, E.New("unknown cache type: " + o.Type)
	}
	if v == nil {
		return json.Marshal((_CacheOptions)(o))
	}
	return badjson.MarshallObjects((_CacheOptions)(o), v)
}

func (o *CacheOptions) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_CacheOptions)(o))
	if err != nil {
		return err
	}
	o.Type = strings.ToLower(strings.TrimSpace(o.Type))
	var v any
	switch o.Type {
	case "", C.CacheTypeMemory:
	case C.CacheTypeRedis:
		v = &o.RedisOptions
	default:
		return E.New("unknown cache type: " + o.Type)
	}
	if v == nil {
		return nil
	}
	return badjson.UnmarshallExcluded(bytes, (*_CacheOptions)(o), v)
}

type RedisCacheOptions struct {
	Address  badoption.Listable[string] `json:"address,omitempty"`
	Username string                     `json:"username,omitempty"`
	Password string                     `json:"password,omitempty"`
	DB       int                        `json:"db,omitempty"`
	Protocol int                        `json:"protocol,omitempty"`
	PoolSize int                        `json:"pool_size,omitempty"`
	option.OutboundTLSOptionsContainer
}
