package hb46pp

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newIPv6TLSServer starts an httptest TLS server bound to the IPv6 loopback
// (httptest defaults to IPv4, which newHTTPClient's dialer -- deliberately,
// per the spec's IPv6-only requirement -- refuses), so tests can exercise
// newHTTPClient's own TLS behavior directly instead of bypassing it via
// Config.httpClient the way discover_test.go's other tests do.
func newIPv6TLSServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	lis, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback available: %v", err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = lis
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestNewHTTPClientValidateCert(t *testing.T) {
	srv := newIPv6TLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	t.Run("t=a skips verification of the self-signed cert", func(t *testing.T) {
		client := newHTTPClient(&fakeResolver{}, false)
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("Get with ValidateCert=false: %v", err)
		}
		resp.Body.Close()
	})

	t.Run("t=b rejects the self-signed cert", func(t *testing.T) {
		client := newHTTPClient(&fakeResolver{}, true)
		_, err := client.Get(srv.URL)
		if err == nil {
			t.Fatal("Get with ValidateCert=true: want error (untrusted self-signed cert), got nil")
		}
	})
}
