package constant

import (
	"strings"

	"github.com/iantsysog/sing-rule/common/semver"
)

type Platform string

const (
	PlatformUnknown Platform = ""
	PlatformSingBox Platform = "sing-box"
)

type System string

const (
	SystemUnknown   System = ""
	SystemAndroid   System = "android"
	SystemiOS       System = "ios"
	SystemMacOS     System = "macos"
	SystemAppleTVOS System = "tvos"
)

type Metadata struct {
	UserAgent string
	Platform  Platform
	System    System
	Version   *semver.Version
}

func DetectMetadata(userAgent string) Metadata {
	metadata := Metadata{UserAgent: userAgent}
	switch {
	case strings.HasPrefix(userAgent, "SFA"):
		metadata.System = SystemAndroid
	case strings.HasPrefix(userAgent, "SFI"):
		metadata.System = SystemiOS
	case strings.HasPrefix(userAgent, "SFM"):
		metadata.System = SystemMacOS
	case strings.HasPrefix(userAgent, "SFT"):
		metadata.System = SystemAppleTVOS
	}
	if index := strings.Index(userAgent, "sing-box "); index >= 0 {
		metadata.Platform = PlatformSingBox
		versionName := userAgent[index+len("sing-box "):]
		if cut := strings.IndexAny(versionName, ";)"); cut >= 0 {
			versionName = versionName[:cut]
		}
		versionName = strings.TrimSpace(versionName)
		if semver.IsValid(versionName) {
			version := semver.ParseVersion(versionName)
			metadata.Version = &version
		}
	}
	return metadata
}
