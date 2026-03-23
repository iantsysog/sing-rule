package constant

import "time"

const DefaultTTL = 5 * time.Minute

type EndpointType = string
type EndpointSource = string

const (
	EndpointTypeFile EndpointType = "file"

	EndpointSourceLocal  EndpointSource = "local"
	EndpointSourceRemote EndpointSource = "remote"
)
