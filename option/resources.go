package option

import (
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
)

type ResourceOptions struct {
	GEOIP   *Resource `json:"geoip,omitempty"`
	GEOSite *Resource `json:"geosite,omitempty"`
	IPASN   *Resource `json:"ipasn,omitempty"`
}

type Resource struct {
	SourceOptions
	SourceConvertOptions
}

func (e Resource) MarshalJSON() ([]byte, error) {
	return badjson.MarshallObjects(e.SourceOptions, e.SourceConvertOptions)
}

func (e *Resource) UnmarshalJSON(bytes []byte) error {
	if e == nil {
		return E.New("nil resource")
	}
	err := json.Unmarshal(bytes, &e.SourceOptions)
	if err != nil {
		return err
	}
	return badjson.UnmarshallExcludedMulti(bytes, &e.SourceOptions, &e.SourceConvertOptions)
}
