package cache

import (
	"context"
	"strings"

	"github.com/iantsysog/sing-rule/adapter"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func New(ctx context.Context, options option.CacheOptions) (adapter.Cache, error) {
	cacheType := strings.ToLower(strings.TrimSpace(options.Type))
	switch cacheType {
	case "", C.CacheTypeMemory:
		return NewMemory(options.Expiration), nil
	case C.CacheTypeRedis:
		return NewRedis(ctx, options.Expiration, options.RedisOptions)
	default:
		return nil, E.New("unknown cache type: ", options.Type)
	}
}
