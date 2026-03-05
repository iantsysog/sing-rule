package asn

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
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
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

type testASNProvider struct {
	calls   atomic.Int32
	prefix  map[string][]string
	err     error
	release <-chan struct{}
}

func (p *testASNProvider) ResolveASN(_ context.Context, asnID string) ([]string, error) {
	p.calls.Add(1)
	if p.release != nil {
		<-p.release
	}
	if p.err != nil {
		return nil, p.err
	}
	return slices.Clone(p.prefix[asnID]), nil
}

func newTestResolver(provider ASNProvider) *ASNResolver {
	return NewASNResolverWithProvider(provider)
}

func TestResolveASN_UsesCacheAndReturnsClones(t *testing.T) {
	t.Parallel()

	provider := &testASNProvider{prefix: map[string][]string{"13335": {"1.1.1.0/24"}}}
	resolver := newTestResolver(provider)

	first, err := resolver.ResolveASN(context.Background(), "AS13335")
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.0/24"}, first)
	first[0] = "changed"

	second, err := resolver.ResolveASN(context.Background(), "13335")
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.0/24"}, second)
	require.EqualValues(t, 1, provider.calls.Load())
}

func TestResolveASN_DeduplicatesConcurrentRequests(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	provider := &testASNProvider{
		prefix:  map[string][]string{"64500": {"203.0.113.0/24"}},
		release: release,
	}
	resolver := newTestResolver(provider)

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
	require.EqualValues(t, 1, provider.calls.Load())
}

func TestResolveASNs_ResolvesAllInputs(t *testing.T) {
	t.Parallel()

	provider := &testASNProvider{prefix: map[string][]string{
		"64512": {"10.10.0.0/16"},
		"64513": {"10.20.0.0/16"},
	}}
	resolver := newTestResolver(provider)

	prefixes, err := resolver.ResolveASNs(context.Background(), []string{"AS64512", "AS64513"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"10.10.0.0/16", "10.20.0.0/16"}, prefixes)
}

func TestResolveASNs_MergesOverlappingPrefixes(t *testing.T) {
	t.Parallel()

	provider := &testASNProvider{prefix: map[string][]string{
		"44907": {"91.108.20.0/23", "91.108.20.0/22", "2001:b28:f23c::/48"},
	}}
	resolver := newTestResolver(provider)

	prefixes, err := resolver.ResolveASNs(context.Background(), []string{"AS44907"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"91.108.20.0/22", "2001:b28:f23c::/48"}, prefixes)
}

func TestMergePrefixes_MergesOverlapsDirectly(t *testing.T) {
	t.Parallel()

	resolver := newTestResolver(&testASNProvider{prefix: map[string][]string{}})
	merged := resolver.mergePrefixes([]string{
		"91.108.20.0/23",
		"91.108.20.0/22",
		"2001:b28:f23c::/48",
	})
	require.ElementsMatch(t, []string{"91.108.20.0/22", "2001:b28:f23c::/48"}, merged)
}

func TestRIPEASNProvider_ResolveASN_ParsesPrefixes(t *testing.T) {
	t.Parallel()

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, "stat.ripe.net", req.URL.Host)
			require.Equal(t, "AS44907", req.URL.Query().Get("resource"))
			return newJSONResponse(req, http.StatusOK, `{
				"status":"ok",
				"data":{
					"prefixes":[
						{"prefix":"91.108.20.0/23"},
						{"prefix":"91.108.20.0/22"},
						{"prefix":"2001:b28:f23c::/48"}
					]
				}
			}`), nil
		}),
	}
	provider := NewRIPEASNProvider(client)

	prefixes, err := provider.ResolveASN(context.Background(), "44907")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"91.108.20.0/23", "91.108.20.0/22", "2001:b28:f23c::/48"}, prefixes)
}

func TestConvertDefaultRuleIPASN_ClearsASNAndAppendsCIDR(t *testing.T) {
	t.Parallel()

	provider := &testASNProvider{prefix: map[string][]string{
		"64520": {"198.51.100.0/24"},
		"64521": {"203.0.113.0/24"},
	}}
	resolver := newTestResolver(provider)

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
	t.Parallel()

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
