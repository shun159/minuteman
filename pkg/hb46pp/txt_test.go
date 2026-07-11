package hb46pp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestParseTXTRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		want    ServerInfo
		wantErr bool
	}{
		{
			name:   "spec example, t=b",
			record: "v=v6mig-1 url=https://vne.example.jp/rule.cgi t=b",
			want:   ServerInfo{URL: "https://vne.example.jp/rule.cgi", ValidateCert: true},
		},
		{
			name:   "t=a with http",
			record: "v=v6mig-1 url=http://vne.example.jp/rule.cgi t=a",
			want:   ServerInfo{URL: "http://vne.example.jp/rule.cgi", ValidateCert: false},
		},
		{
			name:   "unknown keys ignored",
			record: "v=v6mig-1 url=https://vne.example.jp/rule.cgi t=b x=y",
			want:   ServerInfo{URL: "https://vne.example.jp/rule.cgi", ValidateCert: true},
		},
		{name: "wrong version", record: "v=v6mig-2 url=https://a.example/x t=b", wantErr: true},
		{name: "missing version", record: "url=https://a.example/x t=b", wantErr: true},
		{name: "missing url", record: "v=v6mig-1 t=b", wantErr: true},
		{name: "missing t", record: "v=v6mig-1 url=https://a.example/x", wantErr: true},
		{name: "bad t", record: "v=v6mig-1 url=https://a.example/x t=c", wantErr: true},
		{
			name:   "t=a with https",
			record: "v=v6mig-1 url=https://a.example/x t=a",
			want:   ServerInfo{URL: "https://a.example/x", ValidateCert: false},
		},
		{name: "t=b with http", record: "v=v6mig-1 url=http://a.example/x t=b", wantErr: true},
		{name: "url without host", record: "v=v6mig-1 url=https:///x t=b", wantErr: true},
		{name: "empty", record: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTXTRecord(tt.record)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseTXTRecord(%q) = %+v, want error", tt.record, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTXTRecord(%q): %v", tt.record, err)
			}
			if *got != tt.want {
				t.Fatalf("parseTXTRecord(%q) = %+v, want %+v", tt.record, *got, tt.want)
			}
		})
	}
}

// fakeResolver implements resolver from canned data.
type fakeResolver struct {
	txt    map[string][]string
	txtErr error
	aaaa   map[string][]netip.Addr
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.txtErr != nil {
		return nil, f.txtErr
	}
	recs, ok := f.txt[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return recs, nil
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addrs, ok := f.aaaa[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

func TestLookupServerNXDOMAINIsNotProvisioned(t *testing.T) {
	res := &fakeResolver{txt: map[string][]string{}} // no record for 4over6.info
	_, err := lookupServer(context.Background(), res)
	if !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("lookupServer with NXDOMAIN: err = %v, want ErrNotProvisioned", err)
	}
}

func TestLookupServerUnparseableIsNotProvisioned(t *testing.T) {
	res := &fakeResolver{txt: map[string][]string{
		discoveryDomain: {"v=spf1 -all"},
	}}
	_, err := lookupServer(context.Background(), res)
	if !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("lookupServer with unparseable record: err = %v, want ErrNotProvisioned", err)
	}
}

func TestLookupServerTransientFailureIsNotNotProvisioned(t *testing.T) {
	res := &fakeResolver{txtErr: &net.DNSError{Err: "timeout", IsTimeout: true}}
	_, err := lookupServer(context.Background(), res)
	if err == nil {
		t.Fatal("lookupServer with DNS timeout: want error, got nil")
	}
	if errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("lookupServer with DNS timeout: err = %v, must not be ErrNotProvisioned", err)
	}
}

func TestLookupServerSkipsForeignRecords(t *testing.T) {
	res := &fakeResolver{txt: map[string][]string{
		discoveryDomain: {
			"v=spf1 -all",
			"v=v6mig-1 url=https://vne.example.jp/rule.cgi t=b",
		},
	}}
	got, err := lookupServer(context.Background(), res)
	if err != nil {
		t.Fatalf("lookupServer: %v", err)
	}
	if got.URL != "https://vne.example.jp/rule.cgi" {
		t.Fatalf("lookupServer picked %q, want the v6mig-1 record's URL", got.URL)
	}
}
