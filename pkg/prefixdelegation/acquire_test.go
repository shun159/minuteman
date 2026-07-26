package prefixdelegation

import (
	"testing"
	"time"

	"github.com/shun159/miniteman/pkg/dhcpv6"
)

// replyWith builds the minimal Reply usableIAPD looks at: a server DUID
// and one IA_PD.
func replyWith(iapd IAPD) *dhcpv6.Message {
	return &dhcpv6.Message{
		Type: dhcpv6.MessageTypeReply,
		Options: dhcpv6.Options{
			{Code: dhcpv6.OptionServerID, Data: []byte{0x00, 0x03, 0xde, 0xad}},
			IAPDOption(iapd),
		},
	}
}

func TestUsableIAPD(t *testing.T) {
	granted := []IAPrefix{prefixWithLifetimes(time.Hour, 2*time.Hour)}

	t.Run("accepts a granted IA_PD", func(t *testing.T) {
		got, serverID, err := usableIAPD(replyWith(IAPD{
			IAID:     clientIAID,
			T1:       1800 * time.Second,
			T2:       2880 * time.Second,
			Prefixes: granted,
		}))
		if err != nil {
			t.Fatalf("usableIAPD: %v", err)
		}
		if len(got.Prefixes) != 1 || got.Prefixes[0].Prefix != granted[0].Prefix {
			t.Errorf("Prefixes = %v, want %v", got.Prefixes, granted)
		}
		if len(serverID) == 0 {
			t.Error("serverID is empty, want the Reply's OPTION_SERVERID")
		}
	})

	// RFC 9915 §21.21: T1 > T2, both non-zero, means discard the option.
	t.Run("discards T1 greater than T2", func(t *testing.T) {
		_, _, err := usableIAPD(replyWith(IAPD{
			IAID:     clientIAID,
			T1:       2880 * time.Second,
			T2:       1800 * time.Second,
			Prefixes: granted,
		}))
		if err == nil {
			t.Fatal("expected an error for T1 > T2 > 0, got nil")
		}
	})

	// ... but T1 > T2 with T2 == 0 is the server leaving the rebind time
	// to the client (§14.2), not an invalid option.
	t.Run("accepts T1 greater than a zero T2", func(t *testing.T) {
		if _, _, err := usableIAPD(replyWith(IAPD{
			IAID:     clientIAID,
			T1:       1800 * time.Second,
			Prefixes: granted,
		})); err != nil {
			t.Fatalf("usableIAPD: %v", err)
		}
	})

	t.Run("rejects an IA_PD with no prefixes", func(t *testing.T) {
		if _, _, err := usableIAPD(replyWith(IAPD{IAID: clientIAID})); err == nil {
			t.Fatal("expected an error for a prefix-less IA_PD, got nil")
		}
	})

	// RFC 9915 §21.22: a prefix whose preferred lifetime exceeds its
	// valid lifetime is discarded -- individually, so the rest of the
	// IA_PD survives.
	t.Run("discards a prefix with preferred beyond valid", func(t *testing.T) {
		got, _, err := usableIAPD(replyWith(IAPD{
			IAID: clientIAID,
			Prefixes: []IAPrefix{
				prefixWithLifetimes(2*time.Hour, time.Hour),
				granted[0],
			},
		}))
		if err != nil {
			t.Fatalf("usableIAPD: %v", err)
		}
		if len(got.Prefixes) != 1 || got.Prefixes[0].PreferredLifetime != granted[0].PreferredLifetime {
			t.Errorf("Prefixes = %v, want only the valid one (%v)", got.Prefixes, granted)
		}
	})

	t.Run("rejects an IA_PD whose only prefix is discarded", func(t *testing.T) {
		_, _, err := usableIAPD(replyWith(IAPD{
			IAID:     clientIAID,
			Prefixes: []IAPrefix{prefixWithLifetimes(2*time.Hour, time.Hour)},
		}))
		if err == nil {
			t.Fatal("expected an error when every prefix is discarded, got nil")
		}
	})

	t.Run("rejects a failure status", func(t *testing.T) {
		msg := replyWith(IAPD{IAID: clientIAID, Prefixes: granted})
		iapdOpt, _ := msg.Options.Get(dhcpv6.OptionIAPD)
		status := dhcpv6.Options{{
			Code: dhcpv6.OptionStatusCode,
			Data: []byte{0x00, byte(StatusNoPrefixAvail)},
		}}.Marshal()
		iapdOpt.Data = append(iapdOpt.Data, status...)
		msg.Options[1] = iapdOpt

		if _, _, err := usableIAPD(msg); err == nil {
			t.Fatal("expected an error for a NoPrefixAvail IA_PD, got nil")
		}
	})
}
