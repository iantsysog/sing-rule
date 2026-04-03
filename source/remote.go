package source

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/iantsysog/sing-rule/adapter"
	C "github.com/iantsysog/sing-rule/constant"
	"github.com/iantsysog/sing-rule/option"
	boxAdapter "github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

var _ adapter.Source = (*Remote)(nil)

type Remote struct {
	ctx          context.Context
	pathTemplate *template.Template
	httpClient   *http.Client
	userAgent    string
	ttl          time.Duration
	timeout      time.Duration
	contextMode  string
}

func NewRemote(ctx context.Context, options option.SourceOptions) (*Remote, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	pathTemplate := template.New("remote_url").Funcs(template.FuncMap{
		"toLower": strings.ToLower,
		"toUpper": strings.ToUpper,
	})
	if _, err := pathTemplate.Parse(options.RemoteOptions.URL); err != nil {
		return nil, err
	}

	var serverAddress string
	if serverURL, err := url.Parse(options.RemoteOptions.URL); err == nil {
		if hostname := serverURL.Hostname(); M.IsDomainName(hostname) {
			serverAddress = hostname
		}
	}

	remoteDialer, err := dialer.NewDefault(ctx, options.RemoteOptions.DialerOptions)
	if err != nil {
		return nil, err
	}

	var tlsConfig tls.Config
	if options.RemoteOptions.TLS != nil && options.RemoteOptions.TLS.Enabled {
		tlsConfig, err = tls.NewClient(ctx, logger.NOP(), serverAddress, common.PtrValueOrDefault(options.RemoteOptions.TLS))
		if err != nil {
			return nil, E.Cause(err, "initialize TLS configuration")
		}
	}

	dnsTransport := common.Must1(local.NewTransport(ctx, logger.NOP(), "", boxOption.LocalDNSServerOptions{}))
	resolver := dns.NewClient(dns.ClientOptions{Logger: logger.NOP()})
	dialRemote := func(ctx context.Context, network, addr string) (net.Conn, error) {
		destination := M.ParseSocksaddr(addr)
		if M.IsDomainName(destination.Fqdn) {
			addresses, lookupErr := resolver.Lookup(ctx, dnsTransport, destination.Fqdn, boxAdapter.DNSQueryOptions{}, nil)
			if lookupErr != nil {
				return nil, lookupErr
			}
			return N.DialParallel(ctx, remoteDialer, network, destination, addresses, false, 0)
		}
		return remoteDialer.DialContext(ctx, network, destination)
	}

	httpTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if tlsConfig != nil {
		httpTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialRemote(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn, err := aTLS.ClientHandshake(ctx, conn, tlsConfig)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		}
	} else {
		httpTransport.DialContext = dialRemote
	}

	userAgent := options.RemoteOptions.UserAgent
	if userAgent == "" {
		userAgent = F.ToString("srsc/", C.Version, "(sing-box ", C.CoreVersion(), ")")
	}

	ttl := C.DefaultTTL
	if options.RemoteOptions.TTL > 0 {
		ttl = options.RemoteOptions.TTL.Build()
	}

	requestTimeout := 30 * time.Second
	if options.RemoteOptions.Timeout > 0 {
		requestTimeout = options.RemoteOptions.Timeout.Build()
	}

	contextMode := strings.TrimSpace(options.RemoteOptions.Context)
	if contextMode == "" {
		contextMode = "without_cancel"
	}

	return &Remote{
		ctx:          ctx,
		pathTemplate: pathTemplate,
		httpClient: &http.Client{
			Transport: httpTransport,
			Timeout:   requestTimeout,
		},
		userAgent: userAgent,
		ttl:       ttl,
		timeout:   requestTimeout,
		contextMode: contextMode,
	}, nil
}

func (s *Remote) Path(urlParams map[string]string) (sourcePath string, err error) {
	if s == nil || s.pathTemplate == nil {
		return "", os.ErrInvalid
	}
	pathBuffer := buf.New()
	defer pathBuffer.Release()
	if err = s.pathTemplate.Execute(pathBuffer, urlParams); err != nil {
		return "", err
	}
	return string(pathBuffer.Bytes()), nil
}

func (s *Remote) LastUpdated(_ string) time.Time {
	return time.Time{}
}

func (s *Remote) Fetch(path string, requestBody adapter.FetchRequestBody) (*adapter.FetchResponseBody, error) {
	if s == nil || s.httpClient == nil {
		return nil, E.New("remote source is not initialized")
	}
	if parsedURL, err := url.Parse(path); err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, E.New("fetch source: invalid URL")
	}

	now := time.Now()
	if !requestBody.LastUpdated.IsZero() && now.Sub(requestBody.LastUpdated) < s.ttl {
		return &adapter.FetchResponseBody{NotModified: true, LastUpdated: requestBody.LastUpdated}, nil
	}

	baseCtx := s.ctx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	var requestCtx context.Context
	var cancel context.CancelFunc
	switch s.contextMode {
	case "inherit":
		requestCtx = baseCtx
	case "without_cancel":
		requestCtx = context.WithoutCancel(baseCtx)
	case "background":
		requestCtx = context.Background()
	default:
		return nil, E.New("fetch source: invalid context mode: ", s.contextMode)
	}
	if s.timeout > 0 {
		requestCtx, cancel = context.WithTimeout(requestCtx, s.timeout)
		defer cancel()
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, path, nil)
	if err != nil {
		return nil, E.Cause(err, "create HTTP request")
	}
	request.Header.Set("User-Agent", s.userAgent)
	if requestBody.ETag != "" {
		request.Header.Set("If-None-Match", requestBody.ETag)
	}
	if !requestBody.LastUpdated.IsZero() {
		request.Header.Set("If-Modified-Since", requestBody.LastUpdated.UTC().Format(http.TimeFormat))
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return nil, E.Cause(err, "fetch source: execute HTTP request")
	}
	defer response.Body.Close()

	lastUpdated := now
	if modifiedAt := response.Header.Get("Last-Modified"); modifiedAt != "" {
		if parsedTime, parseErr := time.Parse(http.TimeFormat, modifiedAt); parseErr == nil {
			lastUpdated = parsedTime
		}
	}

	switch response.StatusCode {
	case http.StatusNotModified:
		return &adapter.FetchResponseBody{NotModified: true, LastUpdated: lastUpdated}, nil
	case http.StatusOK:
	default:
		return nil, E.New("fetch source: unexpected HTTP status: ", response.Status)
	}

	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, E.Cause(err, "fetch source: read HTTP response body")
	}
	if len(content) == 0 {
		return nil, errors.New("fetch source: empty HTTP response")
	}

	return &adapter.FetchResponseBody{
		Content:     content,
		ETag:        response.Header.Get("ETag"),
		LastUpdated: lastUpdated,
	}, nil
}
