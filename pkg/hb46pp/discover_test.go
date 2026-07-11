package hb46pp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// newTestConfig wires a Discover Config against an httptest server: the
// fake resolver's TXT record points at the server, and the server's own
// (loopback, IPv4) client replaces the IPv6-only production one -- with
// the same CheckRedirect restriction newHTTPClient sets, so tests using
// this helper still exercise fetchProvisioning's own 307-only redirect
// handling instead of silently falling back to http.Client's broader
// default (which also follows 301/302/303/308).
func newTestConfig(srv *httptest.Server, res *fakeResolver) Config {
	if res.txt == nil {
		res.txt = map[string][]string{}
	}
	res.txt[discoveryDomain] = []string{"v=v6mig-1 url=" + srv.URL + "/rule.cgi t=a"}
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return Config{
		Client:     validClient(),
		resolver:   res,
		httpClient: client,
	}
}

func TestDiscover(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte(specExampleJSON))
	}))
	defer srv.Close()

	aftrAddr := netip.MustParseAddr("2001:db8::64")
	res := &fakeResolver{aaaa: map[string][]netip.Addr{
		"aftr.example.net": {aftrAddr},
	}}

	result, err := Discover(context.Background(), newTestConfig(srv, res))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if gotQuery != "vendorid=acde48-v6pc_swg_hgw&product=V6MIG-ROUTER&version=1_32&capability=dslite" {
		t.Fatalf("server saw query %q", gotQuery)
	}
	if result.AFTRName != "aftr.example.net" || result.AFTRAddr != aftrAddr {
		t.Fatalf("AFTR = %q/%v, want aftr.example.net/%v", result.AFTRName, result.AFTRAddr, aftrAddr)
	}
	if result.Provisioning.EnablerName != "A VNE" {
		t.Fatalf("EnablerName = %q", result.Provisioning.EnablerName)
	}
	if result.RefreshInterval != 86400*time.Second {
		t.Fatalf("RefreshInterval = %v, want 24h", result.RefreshInterval)
	}
}

func TestDiscoverAFTRAddressLiteral(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{
			"enabler_name": "e", "service_name": "s", "order": ["dslite"],
			"dslite": {"aftr": "2001:db8::2"}
		}`))
	}))
	defer srv.Close()

	// No AAAA data in the resolver: a literal must not need a lookup.
	result, err := Discover(context.Background(), newTestConfig(srv, &fakeResolver{}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if want := netip.MustParseAddr("2001:db8::2"); result.AFTRAddr != want {
		t.Fatalf("AFTRAddr = %v, want %v", result.AFTRAddr, want)
	}
}

func TestDiscoverNoDSLiteParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"enabler_name": "e", "service_name": "s", "order": ["map_e"]}`))
	}))
	defer srv.Close()

	result, err := Discover(context.Background(), newTestConfig(srv, &fakeResolver{}))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if result.AFTRAddr.IsValid() || result.AFTRName != "" {
		t.Fatalf("AFTR = %q/%v, want zero values when the response has no dslite params", result.AFTRName, result.AFTRAddr)
	}
}

func TestDiscoverRejectedSourceAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "who are you", http.StatusForbidden)
	}))
	defer srv.Close()

	if _, err := Discover(context.Background(), newTestConfig(srv, &fakeResolver{})); err == nil {
		t.Fatal("Discover against a 403 server: want error, got nil")
	}
}

func TestDiscoverFollowsRedirect(t *testing.T) {
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"enabler_name": "e", "service_name": "s", "order": ["dslite"], "dslite": {"aftr": "2001:db8::2"}}`))
	}))
	defer real.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, real.URL+"/rule.cgi?"+r.URL.RawQuery, http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()

	result, err := Discover(context.Background(), newTestConfig(redirecting, &fakeResolver{}))
	if err != nil {
		t.Fatalf("Discover through a 307: %v", err)
	}
	if want := netip.MustParseAddr("2001:db8::2"); result.AFTRAddr != want {
		t.Fatalf("AFTRAddr = %v, want %v", result.AFTRAddr, want)
	}
}

func TestDiscoverDoesNotFollow308(t *testing.T) {
	// The spec (§3.3) defines only 307 as a forward-to-another-server
	// signal; a 308 (which http.Client's default policy would otherwise
	// also follow) must be treated as just another non-200 status.
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the 308's target must not be requested")
	}))
	defer real.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, real.URL+"/rule.cgi?"+r.URL.RawQuery, http.StatusPermanentRedirect)
	}))
	defer srv.Close()

	if _, err := Discover(context.Background(), newTestConfig(srv, &fakeResolver{})); err == nil {
		t.Fatal("Discover through a 308: want error, got nil")
	}
}

func TestDiscoverTooManyRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/rule.cgi?"+r.URL.RawQuery, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	_, err := Discover(context.Background(), newTestConfig(srv, &fakeResolver{}))
	if err == nil {
		t.Fatal("Discover with a redirect loop: want error, got nil")
	}
}

func TestRetryDelayClasses(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		min, max time.Duration
	}{
		{"not provisioned", ErrNotProvisioned, notProvisionedMin, notProvisionedMax},
		{"transient dns", &net.DNSError{Err: "timeout", IsTimeout: true}, dnsFailureMin, dnsFailureMax},
		{"http", errors.New("hb46pp: provisioning server returned 500"), httpFailureMin, httpFailureMax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RetryDelay(tt.err)
			if got < tt.min || got > tt.max {
				t.Fatalf("RetryDelay(%v) = %v, want within [%v, %v]", tt.err, got, tt.min, tt.max)
			}
		})
	}
}
