package asn

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/iantsysog/sing-rule/adapter"
	boxConstant "github.com/sagernet/sing-box/constant"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newJSONResponse(req *http.Request, statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func newTestResolver(rt http.RoundTripper) *ASNResolver {
	return &ASNResolver{
		client:    &http.Client{Transport: rt},
		userAgent: "test-agent",
	}
}

func TestResolveASN_UsesCacheAndReturnsClones(t *testing.T) {
	var bgpCalls atomic.Int32
	resolver := newTestResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.bgpview.io" {
			bgpCalls.Add(1)
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"ipv4_prefixes":[{"prefix":"1.1.1.0/24"}],"ipv6_prefixes":[]}}`), nil
		}
		return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"prefixes":[]}}`), nil
	}))

	first, err := resolver.ResolveASN(context.Background(), "AS13335")
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.0/24"}, first)
	first[0] = "changed"

	second, err := resolver.ResolveASN(context.Background(), "13335")
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.0/24"}, second)
	require.EqualValues(t, 1, bgpCalls.Load())
}

func TestResolveASN_FallsBackToRIPE(t *testing.T) {
	resolver := newTestResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.bgpview.io" {
			return newJSONResponse(req, http.StatusInternalServerError, `{"status":"error"}`), nil
		}
		if req.URL.Host == "stat.ripe.net" && req.URL.Query().Get("resource") == "AS15169" {
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"prefixes":[{"prefix":"8.8.8.0/24"}]}}`), nil
		}
		return newJSONResponse(req, http.StatusNotFound, `{"status":"error"}`), nil
	}))

	prefixes, err := resolver.ResolveASN(context.Background(), "15169")
	require.NoError(t, err)
	require.Equal(t, []string{"8.8.8.0/24"}, prefixes)
}

func TestResolveASN_DeduplicatesConcurrentRequests(t *testing.T) {
	var (
		bgpCalls atomic.Int32
		release  = make(chan struct{})
	)

	resolver := newTestResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.bgpview.io" {
			bgpCalls.Add(1)
			<-release
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"ipv4_prefixes":[{"prefix":"203.0.113.0/24"}],"ipv6_prefixes":[]}}`), nil
		}
		return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"prefixes":[]}}`), nil
	}))

	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			_, err := resolver.ResolveASN(context.Background(), "AS64500")
			errCh <- err
		}()
	}

	close(release)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, bgpCalls.Load())
}

func TestResolveASNs_ResolvesAllInputs(t *testing.T) {
	resolver := newTestResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.bgpview.io" {
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"prefixes":[]}}`), nil
		}
		switch req.URL.Path {
		case "/asn/64512/prefixes":
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"ipv4_prefixes":[{"prefix":"10.10.0.0/16"}],"ipv6_prefixes":[]}}`), nil
		case "/asn/64513/prefixes":
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"ipv4_prefixes":[{"prefix":"10.20.0.0/16"}],"ipv6_prefixes":[]}}`), nil
		default:
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"ipv4_prefixes":[],"ipv6_prefixes":[]}}`), nil
		}
	}))

	prefixes, err := resolver.ResolveASNs(context.Background(), []string{"AS64512", "AS64513"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"10.10.0.0/16", "10.20.0.0/16"}, prefixes)
}

func TestConvertDefaultRuleIPASN_ClearsASNAndAppendsCIDR(t *testing.T) {
	resolver := newTestResolver(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.bgpview.io" {
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"prefixes":[]}}`), nil
		}
		switch req.URL.Path {
		case "/asn/64520/prefixes":
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"ipv4_prefixes":[{"prefix":"198.51.100.0/24"}],"ipv6_prefixes":[]}}`), nil
		case "/asn/64521/prefixes":
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"ipv4_prefixes":[{"prefix":"203.0.113.0/24"}],"ipv6_prefixes":[]}}`), nil
		default:
			return newJSONResponse(req, http.StatusOK, `{"status":"ok","data":{"ipv4_prefixes":[],"ipv6_prefixes":[]}}`), nil
		}
	}))

	rule := &adapter.DefaultRule{
		DefaultHeadlessRule: adapter.DefaultRule{}.DefaultHeadlessRule,
		IPASN:               []string{"AS64520"},
		SourceIPASN:         []string{"64521"},
	}
	rule.IPCIDR = append(rule.IPCIDR, "192.0.2.0/24")

	err := convertDefaultRuleIPASN(context.Background(), resolver, rule)
	require.NoError(t, err)
	require.Nil(t, rule.IPASN)
	require.Nil(t, rule.SourceIPASN)
	require.ElementsMatch(t, []string{"192.0.2.0/24", "198.51.100.0/24"}, []string(rule.IPCIDR))
	require.ElementsMatch(t, []string{"203.0.113.0/24"}, []string(rule.SourceIPCIDR))
}

func TestWalkRules_VisitsLogicalChildren(t *testing.T) {
	rules := []adapter.Rule{
		{
			Type: boxConstant.RuleTypeLogical,
			LogicalOptions: adapter.LogicalRule{
				Rules: []adapter.Rule{
					{Type: boxConstant.RuleTypeDefault},
					{
						Type: boxConstant.RuleTypeLogical,
						LogicalOptions: adapter.LogicalRule{
							Rules: []adapter.Rule{
								{Type: boxConstant.RuleTypeDefault},
							},
						},
					},
				},
			},
		},
	}

	var visited int
	err := walkRules(rules, func(*adapter.Rule) error {
		visited++
		return nil
	})

	require.NoError(t, err)
	require.Equal(t, 4, visited)
}
