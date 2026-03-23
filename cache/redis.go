package cache

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/iantsysog/sing-rule/adapter"
	"github.com/iantsysog/sing-rule/option"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/logger"

	"github.com/redis/rueidis"
)

var _ adapter.Cache = (*RedisCache)(nil)

type RedisCache struct {
	ctx        context.Context
	client     rueidis.Client
	expiration time.Duration
}

func NewRedis(ctx context.Context, expiration time.Duration, options option.RedisCacheOptions) (*RedisCache, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		address []string
		server  string
	)
	if len(options.Address) > 0 {
		address = options.Address
		if firstHost, _, err := net.SplitHostPort(options.Address[0]); err == nil {
			server = firstHost
		} else {
			server = options.Address[0]
		}
	} else {
		address = []string{"localhost:6379"}
		server = "localhost"
	}
	for i, addr := range address {
		address[i] = strings.TrimSpace(addr)
		if address[i] == "" {
			return nil, errors.New("redis address cannot be empty")
		}
	}
	var stdConfig *tls.STDConfig
	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewClient(ctx, logger.NOP(), server, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		stdConfig, err = tlsConfig.STDConfig()
		if err != nil {
			return nil, err
		}
	}
	clientOption := rueidis.ClientOption{
		InitAddress:  address,
		Username:     options.Username,
		Password:     options.Password,
		SelectDB:     options.DB,
		TLSConfig:    stdConfig,
		DisableCache: true,
	}
	if options.Protocol == 2 {
		clientOption.AlwaysRESP2 = true
	}
	if options.PoolSize > 0 {
		clientOption.BlockingPoolSize = options.PoolSize
	}
	client, err := rueidis.NewClient(clientOption)
	if err != nil {
		return nil, err
	}
	return &RedisCache{
		ctx:        ctx,
		client:     client,
		expiration: expiration,
	}, nil
}

func (r *RedisCache) Start() error {
	return nil
}

func (r *RedisCache) Close() error {
	if r.client == nil {
		return nil
	}
	r.client.Close()
	return nil
}

func (r *RedisCache) LoadBinary(tag string) (*adapter.SavedBinary, error) {
	if r.client == nil {
		return nil, errors.New("redis cache is not initialized")
	}
	resp := r.client.Do(r.ctx, r.client.B().Get().Key(tag).Build())
	if err := resp.Error(); err != nil {
		if rueidis.IsRedisNil(err) {
			return nil, nil
		}
		return nil, err
	}
	binaryBytes, err := resp.AsBytes()
	if err != nil {
		return nil, err
	}
	binary := &adapter.SavedBinary{}
	err = binary.UnmarshalBinary(binaryBytes)
	if err != nil {
		return nil, err
	}
	return binary, nil
}

func (r *RedisCache) SaveBinary(tag string, binary *adapter.SavedBinary) error {
	if r.client == nil {
		return errors.New("redis cache is not initialized")
	}
	if binary == nil {
		return r.client.Do(r.ctx, r.client.B().Del().Key(tag).Build()).Error()
	}
	binaryBytes, err := binary.MarshalBinary()
	if err != nil {
		return err
	}
	var cmd rueidis.Completed
	if r.expiration > 0 {
		cmd = r.client.B().Set().Key(tag).Value(string(binaryBytes)).Ex(r.expiration).Build()
	} else {
		cmd = r.client.B().Set().Key(tag).Value(string(binaryBytes)).Build()
	}
	if err = r.client.Do(r.ctx, cmd).Error(); err != nil {
		return err
	}
	return nil
}
