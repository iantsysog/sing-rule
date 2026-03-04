package source

import (
	"context"

	"github.com/iantsysog/sing-rule/adapter"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func New(ctx context.Context, options option.SourceOptions) (adapter.Source, error) {
	switch options.Source {
	case C.EndpointSourceLocal:
		return NewLocal(ctx, options)
	case C.EndpointSourceRemote:
		return NewRemote(ctx, options)
	default:
		return nil, E.New("unknown source type: " + options.Source)
	}
}
