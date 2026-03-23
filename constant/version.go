package constant

import (
	"runtime/debug"
	"sync"
)

var (
	Version = ""

	coreVersionFunc = sync.OnceValue(func() string {
		buildInfo, loaded := debug.ReadBuildInfo()
		if !loaded {
			return "unknown"
		}
		for _, dependency := range buildInfo.Deps {
			if dependency.Path == "github.com/sagernet/sing-box" {
				if dependency.Version != "" {
					return dependency.Version
				}
				return "unknown"
			}
		}
		return "unknown"
	})
)

func CoreVersion() string {
	return coreVersionFunc()
}
