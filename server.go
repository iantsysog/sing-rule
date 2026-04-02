package srsc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/iantsysog/sing-rule/adapter"
	"github.com/iantsysog/sing-rule/cache"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/endpoint"
	"github.com/iantsysog/sing-rule/option"
	"github.com/iantsysog/sing-rule/resource"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/http2"
)

type Server struct {
	createdAt  time.Time
	ctx        context.Context
	logger     logger.ContextLogger
	logFactory log.Factory
	listener   *listener.Listener
	tlsConfig  tls.ServerConfig
	httpServer *http.Server
	cache      adapter.Cache
}

type Options struct {
	Context context.Context
	Logger  logger.ContextLogger
	option.Options
}

func NewServer(options Options) (*Server, error) {
	createdAt := time.Now()
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = service.ContextWithDefaultRegistry(ctx)

	var (
		logFactory log.Factory
		err        error
	)
	if options.Logger == nil {
		logFactory, err = log.New(log.Options{
			Context:  ctx,
			Options:  common.PtrValueOrDefault(options.Log),
			BaseTime: createdAt,
		})
		if err != nil {
			return nil, E.Cause(err, "create log factory")
		}
		options.Logger = logFactory.Logger()
	}

	serviceCache, err := cache.New(ctx, common.PtrValueOrDefault(options.Cache))
	if err != nil {
		return nil, E.Cause(err, "create cache")
	}
	service.MustRegister(ctx, serviceCache)

	resourceManager, err := resource.NewManager(ctx, options.Logger, common.PtrValueOrDefault(options.Resources))
	if err != nil {
		return nil, E.Cause(err, "initialize resource manager")
	}
	service.MustRegister[adapter.ResourceManager](ctx, resourceManager)

	router := chi.NewRouter()
	s := &Server{
		createdAt:  createdAt,
		ctx:        ctx,
		logger:     options.Logger,
		logFactory: logFactory,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  options.Logger,
			Network: []string{N.NetworkTCP},
			Listen: boxOption.ListenOptions{
				Listen:     options.Listen,
				ListenPort: options.ListenPort,
			},
		}),
		cache: serviceCache,
	}

	if options.Endpoints == nil || options.Endpoints.Size() == 0 {
		return nil, E.New("missing endpoints")
	}
	for index, entry := range options.Endpoints.Entries() {
		if !strings.HasPrefix(entry.Key, "/") {
			return nil, E.New("route pattern must start with '/': [", index, "]: ", entry.Key)
		}
		switch entry.Value.Type {
		case C.EndpointTypeFile:
			handler, handlerErr := endpoint.NewFileEndpoint(ctx, options.Logger, index, entry.Value.FileOptions)
			if handlerErr != nil {
				return nil, E.Cause(handlerErr, "initialize file endpoint")
			}
			router.Get(entry.Key, handler.ServeHTTP)
		default:
			return nil, E.New("unsupported endpoint type: ", entry.Value.Type)
		}
	}

	s.httpServer = &http.Server{
		Handler:           router,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	if options.TLS != nil {
		tlsConfig, tlsErr := tls.NewServer(ctx, options.Logger, common.PtrValueOrDefault(options.TLS))
		if tlsErr != nil {
			return nil, tlsErr
		}
		s.tlsConfig = tlsConfig
	}

	return s, nil
}

func (s *Server) Start() error {
	if s.logFactory != nil {
		if err := s.logFactory.Start(); err != nil {
			return E.Cause(err, "start log factory")
		}
	}
	if s.cache != nil {
		if err := s.cache.Start(); err != nil {
			return E.Cause(err, "start cache")
		}
	}
	if s.tlsConfig != nil {
		if err := s.tlsConfig.Start(); err != nil {
			return E.Cause(err, "initialize TLS configuration")
		}
	}
	if s.listener == nil || s.httpServer == nil {
		return E.New("server is not initialized")
	}

	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	if s.tlsConfig != nil {
		if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, s.tlsConfig.NextProtos()...))
		}
		tcpListener = aTLS.NewListener(tcpListener, s.tlsConfig)
	}

	go func() {
		serveErr := s.httpServer.Serve(tcpListener)
		if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
			s.logger.Error("http server stopped with error: ", serveErr)
		}
	}()

	s.logger.Info("srsc started (", F.Seconds(time.Since(s.createdAt).Seconds()), "s)")
	return nil
}

func (s *Server) Close() error {
	var serverErr error
	if s.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		serverErr = s.httpServer.Shutdown(shutdownCtx)
	}
	return errors.Join(serverErr, common.Close(
		common.PtrOrNil(s.listener),
		s.tlsConfig,
		s.cache,
		s.logFactory,
	))
}
