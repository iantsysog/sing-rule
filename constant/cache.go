package constant

type CacheType = string

const (
	CacheTypeMemory CacheType = "memory"
	CacheTypeRedis  CacheType = "redis"
)
