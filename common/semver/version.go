package semver

import (
	"strconv"
	"strings"

	F "github.com/sagernet/sing/common/format"

	"golang.org/x/mod/semver"
)

type Version struct {
	Major                int
	Minor                int
	Patch                int
	Commit               string
	PreReleaseIdentifier string
	PreReleaseVersion    int
}

func (v Version) LessThan(anotherVersion Version) bool {
	return v.Compare(anotherVersion) < 0
}

func (v Version) LessThanOrEqual(anotherVersion Version) bool {
	return v.Compare(anotherVersion) <= 0
}

func (v Version) GreaterThanOrEqual(anotherVersion Version) bool {
	return v.Compare(anotherVersion) >= 0
}

func (v Version) GreaterThan(anotherVersion Version) bool {
	return v.Compare(anotherVersion) > 0
}

func (v Version) Compare(another Version) int {
	if v.Major != another.Major {
		if v.Major < another.Major {
			return -1
		}
		return 1
	}
	if v.Minor != another.Minor {
		if v.Minor < another.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != another.Patch {
		if v.Patch < another.Patch {
			return -1
		}
		return 1
	}
	if v.PreReleaseIdentifier == "" {
		if another.PreReleaseIdentifier == "" {
			return 0
		}
		return 1
	}
	if another.PreReleaseIdentifier == "" {
		return -1
	}
	leftRank := parsePreReleaseIdentifier(v.PreReleaseIdentifier)
	rightRank := parsePreReleaseIdentifier(another.PreReleaseIdentifier)
	if leftRank != rightRank {
		if leftRank < rightRank {
			return -1
		}
		return 1
	}
	if !strings.EqualFold(v.PreReleaseIdentifier, another.PreReleaseIdentifier) {
		identifierCompare := strings.Compare(strings.ToLower(v.PreReleaseIdentifier), strings.ToLower(another.PreReleaseIdentifier))
		if identifierCompare < 0 {
			return -1
		}
		return 1
	}
	if v.PreReleaseVersion < another.PreReleaseVersion {
		return -1
	}
	if v.PreReleaseVersion > another.PreReleaseVersion {
		return 1
	}
	return 0
}

func parsePreReleaseIdentifier(identifier string) int {
	identifier = strings.ToLower(identifier)
	switch {
	case strings.HasPrefix(identifier, "alpha"):
		return 1
	case strings.HasPrefix(identifier, "beta"):
		return 2
	case strings.HasPrefix(identifier, "rc"):
		return 3
	default:
		return 0
	}
}

func (v Version) String() string {
	version := F.ToString(v.Major, ".", v.Minor, ".", v.Patch)
	if v.PreReleaseIdentifier != "" {
		version = F.ToString(version, "-", v.PreReleaseIdentifier, ".", v.PreReleaseVersion)
	}
	return version
}

func (v Version) BadString() string {
	version := F.ToString(v.Major, ".", v.Minor)
	if v.Patch > 0 {
		version = F.ToString(version, ".", v.Patch)
	}
	if v.PreReleaseIdentifier != "" {
		version = F.ToString(version, "-", v.PreReleaseIdentifier)
		if v.PreReleaseVersion > 0 {
			version = F.ToString(version, v.PreReleaseVersion)
		}
	}
	return version
}

func IsValid(versionName string) bool {
	versionName = strings.TrimSpace(versionName)
	if versionName == "" {
		return false
	}
	if versionName[0] == 'v' || versionName[0] == 'V' {
		return semver.IsValid("v" + versionName[1:])
	}
	return semver.IsValid("v" + versionName)
}

func ParseVersion(versionName string) (version Version) {
	versionName = strings.TrimSpace(versionName)
	if versionName == "" {
		return
	}
	if versionName[0] == 'v' || versionName[0] == 'V' {
		versionName = versionName[1:]
	}
	mainPart, suffix, hasSuffix := strings.Cut(versionName, "-")
	version.Major, version.Minor, version.Patch = parseCoreVersion(mainPart)
	if !hasSuffix || suffix == "" {
		return
	}
	if identifier, releaseVersion, ok := parseDottedPreRelease(suffix); ok {
		version.PreReleaseIdentifier = identifier
		version.PreReleaseVersion = releaseVersion
		return
	}
	identifier, releaseVersion, ok := parseCompactPreRelease(suffix)
	if ok {
		version.PreReleaseIdentifier = identifier
		version.PreReleaseVersion = releaseVersion
		return
	}
	version.Commit = suffix
	return
}

func parseCoreVersion(versionName string) (int, int, int) {
	majorPart, rest, hasMinor := strings.Cut(versionName, ".")
	major := parseNonNegativeInt(majorPart)
	if !hasMinor {
		return major, 0, 0
	}
	minorPart, patchPart, hasPatch := strings.Cut(rest, ".")
	minor := parseNonNegativeInt(minorPart)
	if !hasPatch {
		return major, minor, 0
	}
	return major, minor, parseNonNegativeInt(patchPart)
}

func parseDottedPreRelease(suffix string) (string, int, bool) {
	identifier, releaseVersionRaw, ok := strings.Cut(suffix, ".")
	if !ok || identifier == "" {
		return "", 0, false
	}
	return identifier, parseNonNegativeInt(releaseVersionRaw), true
}

func parseCompactPreRelease(suffix string) (string, int, bool) {
	identifier := strings.ToLower(suffix)
	switch {
	case strings.HasPrefix(identifier, "alpha"):
		return "alpha", parseNonNegativeInt(suffix[len("alpha"):]), true
	case strings.HasPrefix(identifier, "beta"):
		return "beta", parseNonNegativeInt(suffix[len("beta"):]), true
	case strings.HasPrefix(identifier, "rc"):
		return "rc", parseNonNegativeInt(suffix[len("rc"):]), true
	default:
		return "", 0, false
	}
}

func parseNonNegativeInt(raw string) int {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0
	}
	return value
}
