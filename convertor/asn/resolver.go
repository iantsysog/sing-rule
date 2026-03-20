package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	E "github.com/sagernet/sing/common/exceptions"
	"go4.org/netipx"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

const (
	defaultConcurrencyCap = 10
	defaultASNMMDBURL     = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
	downloadTimeout       = 60 * time.Second
	ripeURLTemplate       = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s"
	clientRequestTimeout  = 15 * time.Second
	maxResponseBodyBytes  = 4 << 20
	maxMMDBFileBytes      = 128 << 20
	statusOK              = "ok"
)

type asnMMDBRecord struct {
	AutonomousSystemNumber uint32 `maxminddb:"autonomous_system_number"`
}

type ASNProvider interface {
	ResolveASN(ctx context.Context, asnID string) ([]string, error)
}

type ASNResolver struct {
	cache    sync.Map
	inflight singleflight.Group
	provider ASNProvider
}

type MMDBASNProvider struct {
	index map[string][]string
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
	provider, err := NewMMDBASNProvider()
	if err == nil {
		return NewASNResolverWithProvider(provider), nil
	}
	return NewASNResolverWithProvider(NewRIPEASNProvider(nil)), nil
}

func NewASNResolverWithProvider(provider ASNProvider) *ASNResolver {
	if provider == nil {
		provider = NewRIPEASNProvider(nil)
	}
	return &ASNResolver{provider: provider}
}

func NewMMDBASNProvider() (*MMDBASNProvider, error) {
	path, cleanup, err := downloadASNMMDBToTemp(defaultASNMMDBURL)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return NewMMDBASNProviderFromPath(path)
}

func NewMMDBASNProviderFromPath(path string) (*MMDBASNProvider, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, E.Cause(err, "open ASN MMDB")
	}
	defer db.Close()

	networks := db.Networks(maxminddb.SkipEmptyValues())
	index := make(map[string][]string)

	for result := range networks {
		if err := result.Err(); err != nil {
			return nil, E.Cause(err, "decode ASN MMDB network")
		}

		var record asnMMDBRecord
		if err := result.Decode(&record); err != nil {
			return nil, E.Cause(err, "decode ASN MMDB network")
		}
		if record.AutonomousSystemNumber == 0 {
			continue
		}

		asnID := strconv.FormatUint(uint64(record.AutonomousSystemNumber), 10)
		index[asnID] = append(index[asnID], result.Prefix().String())
	}

	return &MMDBASNProvider{index: index}, nil
}

func (p *MMDBASNProvider) ResolveASN(_ context.Context, asnID string) ([]string, error) {
	prefixes, ok := p.index[asnID]
	if !ok {
		return nil, nil
	}
	return slices.Clone(prefixes), nil
}

func NewRIPEASNProvider(client *http.Client) *RIPEASNProvider {
	if client == nil {
		client = &http.Client{Timeout: clientRequestTimeout}
	}
	return &RIPEASNProvider{client: client}
}

func (p *RIPEASNProvider) ResolveASN(ctx context.Context, asnID string) ([]string, error) {
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

func downloadASNMMDBToTemp(url string) (string, func(), error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", nil, E.Cause(err, "create ASN MMDB download request")
	}

	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, E.Cause(err, "download ASN MMDB")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, E.New("download ASN MMDB failed: ", resp.Status)
	}

	file, err := os.CreateTemp("", "sing-rule-asn-*.mmdb")
	if err != nil {
		return "", nil, E.Cause(err, "create ASN MMDB file")
	}
	path := file.Name()

	body := io.LimitReader(resp.Body, maxMMDBFileBytes+1)
	written, copyErr := io.Copy(file, body)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(path)
		return "", nil, E.Cause(copyErr, "write ASN MMDB file")
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", nil, E.Cause(closeErr, "close ASN MMDB file")
	}
	if written > maxMMDBFileBytes {
		_ = os.Remove(path)
		return "", nil, E.New("ASN MMDB exceeds max allowed size")
	}

	return path, func() { _ = os.Remove(path) }, nil
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

		prefixes, resolveErr := r.provider.ResolveASN(ctx, asnID)
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

	results := make([][]string, len(asns))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(defaultConcurrencyCap)

	for i := range asns {
		i := i
		g.Go(func() error {
			prefixes, err := r.ResolveASN(ctx, asns[i])
			if err != nil {
				return E.Cause(err, "resolve ASN: ", asns[i])
			}
			results[i] = prefixes
			return nil
		})
	}

	if err := g.Wait(); err != nil {
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
