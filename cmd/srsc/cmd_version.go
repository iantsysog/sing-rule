package main

import (
	"io"
	"os"
	"runtime"
	"runtime/debug"

	C "github.com/sagernet/sing-box/constant"
)

func printVersion(nameOnly bool) error {
	if nameOnly {
		_, err := io.WriteString(os.Stdout, C.Version+"\n")
		return err
	}
	version := "srsc version " + C.Version + "\n\n"
	version += "Environment: " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n"

	var tags string
	var revision string

	debugInfo, loaded := debug.ReadBuildInfo()
	if loaded {
		for _, setting := range debugInfo.Settings {
			switch setting.Key {
			case "-tags":
				tags = setting.Value
			case "vcs.revision":
				revision = setting.Value
			}
		}
	}

	if tags != "" {
		version += "Tags: " + tags + "\n"
	}
	if revision != "" {
		version += "Revision: " + revision + "\n"
	}

	if C.CGO_ENABLED {
		version += "CGO: enabled\n"
	} else {
		version += "CGO: disabled\n"
	}

	_, err := io.WriteString(os.Stdout, version)
	return err
}
