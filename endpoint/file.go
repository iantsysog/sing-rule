package endpoint

import (
	"context"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/iantsysog/sing-rule/adapter"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/convertor"
	"github.com/iantsysog/sing-rule/option"
	"github.com/iantsysog/sing-rule/source"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

var _ http.Handler = (*FileEndpoint)(nil)

type FileEndpoint struct {
	ctx             context.Context
	logger          logger.ContextLogger
	cache           adapter.Cache
	index           int
	source          adapter.Source
	sourceConvertor adapter.Convertor
	targetConvertor adapter.Convertor
	convertOptions  option.ConvertOptions
	convertRequired bool
}

func NewFileEndpoint(ctx context.Context, logger logger.ContextLogger, index int, options option.FileEndpoint) (*FileEndpoint, error) {
	ep := &FileEndpoint{
		ctx:             ctx,
		logger:          logger,
		cache:           service.FromContext[adapter.Cache](ctx),
		index:           index,
		convertOptions:  options.ConvertOptions,
		convertRequired: options.ConvertOptions.ConvertRequired(),
	}
	if ep.cache == nil {
		return nil, E.New("cache service is not available")
	}
	endpointSource, err := source.New(ctx, options.SourceOptions)
	if err != nil {
		return nil, E.Cause(err, "create source")
	}
	ep.source = endpointSource
	sourceConvertor, loaded := convertor.Convertors[options.SourceType]
	if !loaded {
		return nil, E.New("unknown source type: ", options.SourceType)
	}
	ep.sourceConvertor = sourceConvertor
	targetConvertor, loaded := convertor.Convertors[options.TargetType]
	if !loaded {
		return nil, E.New("unknown target type: ", options.TargetType)
	}
	ep.targetConvertor = targetConvertor
	return ep, nil
}

func (f *FileEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status, err := f.serve(w, r)
	if err != nil {
		if status > 0 {
			w.WriteHeader(status)
		}
		f.logger.Error("handle ", r.RemoteAddr, " - ", r.UserAgent(), " \"", r.Method, " ", r.URL, " ", r.Proto, "\": ", err)
		return
	}
	f.logger.Debug("accepted ", r.RemoteAddr, " - ", r.UserAgent(), " \"", r.Method, " ", r.URL, " ", r.Proto, "\"")
}

func (f *FileEndpoint) serve(w http.ResponseWriter, r *http.Request) (int, error) {
	convertOptions := adapter.ConvertOptions{
		Options:  f.convertOptions,
		Metadata: C.DetectMetadata(r.UserAgent()),
	}
	cachePath, err := f.source.Path(requestParams(r))
	if err != nil {
		return http.StatusBadRequest, E.Cause(err, "evaluate source path")
	}
	cacheKey := F.ToString("file.", f.index, ".", cachePath)
	cachedBinary, err := f.cache.LoadBinary(cacheKey)
	if err != nil && !os.IsNotExist(err) {
		return http.StatusInternalServerError, E.Cause(err, "load cache binary")
	}
	lastUpdated := f.source.LastUpdated(cachePath)
	if cachedBinary != nil && !lastUpdated.IsZero() && cachedBinary.LastUpdated.Equal(lastUpdated) {
		return 0, f.writeCache(w, cachedBinary, convertOptions)
	}

	var fetchBody adapter.FetchRequestBody
	if cachedBinary != nil {
		fetchBody.ETag = cachedBinary.LastEtag
		fetchBody.LastUpdated = cachedBinary.LastUpdated
	}
	response, err := f.source.Fetch(cachePath, fetchBody)
	if err != nil {
		return http.StatusBadGateway, E.Cause(err, "fetch source")
	}
	if response.NotModified {
		if cachedBinary == nil {
			return http.StatusBadGateway, E.New("fetch source: unexpected not modified response")
		}
		if response.LastUpdated != cachedBinary.LastUpdated {
			cachedBinary.LastUpdated = response.LastUpdated
			if err = f.cache.SaveBinary(cacheKey, cachedBinary); err != nil {
				return http.StatusInternalServerError, E.Cause(err, "save cache binary")
			}
		}
		return 0, f.writeCache(w, cachedBinary, convertOptions)
	}
	if len(response.Content) == 0 {
		return http.StatusBadGateway, E.New("fetch source: empty content")
	}
	binary := response.Content
	if f.convertRequired {
		rules, convertErr := f.sourceConvertor.From(f.ctx, response.Content, convertOptions)
		if convertErr != nil {
			return http.StatusInternalServerError, E.Cause(convertErr, "decode source")
		}
		binary, convertErr = f.targetConvertor.To(f.ctx, rules, convertOptions)
		if convertErr != nil {
			return http.StatusInternalServerError, E.Cause(convertErr, "encode target")
		}
	}
	cachedBinary = &adapter.SavedBinary{
		Content:     binary,
		LastUpdated: response.LastUpdated,
		LastEtag:    response.ETag,
	}
	if err = f.cache.SaveBinary(cacheKey, cachedBinary); err != nil {
		return http.StatusInternalServerError, E.Cause(err, "save cache binary")
	}
	return 0, f.writeCache(w, cachedBinary, convertOptions)
}

func requestParams(r *http.Request) map[string]string {
	routeCtx := chi.RouteContext(r.Context())
	if routeCtx == nil {
		return nil
	}
	count := len(routeCtx.URLParams.Keys)
	if count == 0 {
		return nil
	}
	params := make(map[string]string, count)
	for i := range count {
		params[routeCtx.URLParams.Keys[i]] = routeCtx.URLParams.Values[i]
	}
	return params
}

func (f *FileEndpoint) writeCache(w http.ResponseWriter, cachedBinary *adapter.SavedBinary, convertOptions adapter.ConvertOptions) error {
	if cachedBinary == nil {
		return E.New("cached content is empty")
	}
	header := w.Header()
	header.Set("Content-Type", f.targetConvertor.ContentType(convertOptions)+"; charset=utf-8")
	header.Set("Content-Length", F.ToString(len(cachedBinary.Content)))
	if cachedBinary.LastEtag != "" {
		header.Set("ETag", cachedBinary.LastEtag)
	}
	_, err := w.Write(cachedBinary.Content)
	if err != nil {
		return E.Cause(err, "write cached content")
	}
	return nil
}
