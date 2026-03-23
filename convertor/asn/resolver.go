package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"go4.org/netipx"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

const (
	defaultConcurrencyCap = 10
	ripeURLTemplate       = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s"
	clientRequestTimeout  = 15 * time.Second
	maxResponseBodyBytes  = 4 << 20
	statusOK              = "ok"
)

type ASNProvider interface {
	ResolveASN(ctx context.Context, asnID string) ([]string, error)
}

type ASNResolver struct {
	cache    sync.Map
	inflight singleflight.Group
	provider ASNProvider
}

type ASNPrefix struct {
	Prefix string `json:"prefix"`
}

type RIPEResponse struct {
	Status string `json:"status"`
	Data   struct {
		Prefixes []ASNPrefix `json:"prefixes"`
	} `json:"data"`
}

type RIPEASNProvider struct {
	client *http.Client
}

func NewASNResolver() (*ASNResolver, error) {
	return NewASNResolverWithProvider(NewRIPEASNProvider(nil)), nil
}

func NewASNResolverWithProvider(provider ASNProvider) *ASNResolver {
	if provider == nil {
		provider = NewRIPEASNProvider(nil)
	}
	return &ASNResolver{provider: provider}
}

func NewRIPEASNProvider(client *http.Client) *RIPEASNProvider {
	if client == nil {
		client = &http.Client{Timeout: clientRequestTimeout}
	}
	return &RIPEASNProvider{client: client}
}

func (p *RIPEASNProvider) ResolveASN(ctx context.Context, asnID string) ([]string, error) {
	if p == nil || p.client == nil {
		return nil, E.New("RIPE provider is not initialized")
	}
	var response RIPEResponse
	if err := p.fetchJSON(ctx, fmt.Sprintf(ripeURLTemplate, asnID), &response); err != nil {
		return nil, err
	}
	if response.Status != statusOK {
		return nil, E.New("RIPE API returned status: ", response.Status)
	}

	prefixes := make([]string, 0, len(response.Data.Prefixes))
	for _, prefix := range response.Data.Prefixes {
		if prefix.Prefix != "" {
			prefixes = append(prefixes, prefix.Prefix)
		}
	}
	return prefixes, nil
}

func (p *RIPEASNProvider) fetchJSON(ctx context.Context, url string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return E.Cause(err, "create RIPE request")
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return E.Cause(err, "fetch RIPE API")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return E.New("RIPE API returned status: ", resp.Status)
	}

	body, err := readAllWithLimit(resp.Body, maxResponseBodyBytes)
	if err != nil {
		return E.Cause(err, "read RIPE response")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return E.Cause(err, "decode RIPE response")
	}
	return nil
}

func readAllWithLimit(r io.Reader, limit int64) ([]byte, error) {
	reader := io.LimitReader(r, limit+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, E.New("response exceeds max allowed size")
	}
	return body, nil
}

func normalizeASN(asn string) string {
	value := strings.TrimSpace(asn)
	if len(value) >= 2 && strings.EqualFold(value[:2], "AS") {
		value = value[2:]
	}
	value = strings.TrimSpace(value)
	if len(value) >= 2 && strings.EqualFold(value[len(value)-2:], "AS") {
		value = value[:len(value)-2]
	}
	return strings.TrimSpace(value)
}

func validateASN(asn string) error {
	if asn == "" {
		return E.New("ASN cannot be empty")
	}
	if _, err := strconv.ParseUint(asn, 10, 32); err != nil {
		return E.Cause(err, "invalid ASN format: ", asn)
	}
	return nil
}

func (r *ASNResolver) ResolveASN(ctx context.Context, asn string) ([]string, error) {
	if r == nil || r.provider == nil {
		return nil, E.New("ASN resolver is not initialized")
	}
	asnID := normalizeASN(asn)
	if err := validateASN(asnID); err != nil {
		return nil, err
	}

	if prefixes, ok := r.loadFromCache(asnID); ok {
		return slices.Clone(prefixes), nil
	}

	resolvedAny, err, _ := r.inflight.Do(asnID, func() (any, error) {
		if prefixes, ok := r.loadFromCache(asnID); ok {
			return prefixes, nil
		}

		prefixes, resolveErr := r.provider.ResolveASN(providerContext(ctx), asnID)
		if resolveErr != nil {
			return nil, resolveErr
		}

		cloned := slices.Clone(prefixes)
		r.cache.Store(asnID, cloned)
		return cloned, nil
	})
	if err != nil {
		return nil, err
	}

	prefixes, ok := resolvedAny.([]string)
	if !ok {
		return nil, E.New("invalid cached ASN prefix type")
	}
	return slices.Clone(prefixes), nil
}

func (r *ASNResolver) loadFromCache(asnID string) ([]string, bool) {
	cached, ok := r.cache.Load(asnID)
	if !ok {
		return nil, false
	}

	prefixes, ok := cached.([]string)
	if !ok {
		r.cache.Delete(asnID)
		return nil, false
	}
	return prefixes, true
}

func (r *ASNResolver) ResolveASNs(ctx context.Context, asns []string) ([]string, error) {
	if len(asns) == 0 {
		return nil, nil
	}
	asnList, err := normalizeAndUniqueASNs(asns)
	if err != nil {
		return nil, err
	}

	results := make([][]string, len(asnList))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(defaultConcurrencyCap)

	for i := range asnList {
		g.Go(func() error {
			prefixes, err := r.ResolveASN(ctx, asnList[i])
			if err != nil {
				return E.Cause(err, "resolve ASN: ", asnList[i])
			}
			results[i] = prefixes
			return nil
		})
	}

	if err = g.Wait(); err != nil {
		return nil, err
	}

	total := 0
	for _, prefixes := range results {
		total += len(prefixes)
	}
	allPrefixes := make([]string, 0, total)
	for _, prefixes := range results {
		allPrefixes = append(allPrefixes, prefixes...)
	}

	return r.mergePrefixes(allPrefixes), nil
}

func (r *ASNResolver) mergePrefixes(prefixes []string) []string {
	if len(prefixes) == 0 {
		return nil
	}

	var builder netipx.IPSetBuilder
	for _, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		builder.AddPrefix(prefix)
	}

	ipSet, err := builder.IPSet()
	if err != nil {
		return slices.Clone(prefixes)
	}

	result := make([]string, 0, len(prefixes))
	for _, ipRange := range ipSet.Ranges() {
		for _, prefix := range ipRange.Prefixes() {
			result = append(result, prefix.String())
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func normalizeAndUniqueASNs(asns []string) ([]string, error) {
	result := make([]string, 0, len(asns))
	seen := make(map[string]struct{}, len(asns))
	for _, asn := range asns {
		asnID := normalizeASN(asn)
		if err := validateASN(asnID); err != nil {
			return nil, err
		}
		if _, exists := seen[asnID]; exists {
			continue
		}
		seen[asnID] = struct{}{}
		result = append(result, asnID)
	}
	return result, nil
}

func providerContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}
