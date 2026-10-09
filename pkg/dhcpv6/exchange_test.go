package dhcpv6

import (
	"testing"
	"time"
)

var (
	ourDUID   = NewDUIDLL(1, []byte{0, 1, 2, 3, 4, 5})
	theirDUID = NewDUIDLL(1, []byte{6, 7, 8, 9, 10, 11})
	testXID   = TransactionID{1, 2, 3}
)

func TestExchangeMessage(t *testing.T) {
	x := Exchange{Type: MessageTypeSolicit, Expect: MessageTypeAdvertise, Options: Options{NewORO(OptionDNSServers)}}
	m := x.Message(testXID, ourDUID, 1500*time.Millisecond)
	if m.Type != MessageTypeSolicit || m.XID != testXID {
		t.Fatalf("message %v %v", m.Type, m.XID)
	}
	if len(m.Options) != 3 || m.Options[0].Code != OptionClientID || m.Options[1].Code != OptionORO || m.Options[2].Code != OptionElapsedTime {
		t.Fatalf("options %+v, want CLIENTID, ORO, ELAPSED_TIME", m.Options)
	}
	if id, _ := m.Options.ClientID(); string(id) != string(ourDUID) {
		t.Errorf("client ID %x", id)
	}
}

func TestExchangeAnswers(t *testing.T) {
	x := Exchange{Type: MessageTypeRequest, Expect: MessageTypeReply}
	reply := func(typ MessageType, xid TransactionID, opts ...Option) *Message {
		return &Message{Type: typ, XID: xid, Options: opts}
	}
	server := Option{Code: OptionServerID, Data: theirDUID}
	tests := []struct {
		name string
		msg  *Message
		want bool
	}{
		{"valid", reply(MessageTypeReply, testXID, server, NewClientIDOption(ourDUID)), true},
		{"no client ID echoed", reply(MessageTypeReply, testXID, server), true},
		{"other type", reply(MessageTypeAdvertise, testXID, server), false},
		{"other transaction", reply(MessageTypeReply, TransactionID{9, 9, 9}, server), false},
		{"no server ID", reply(MessageTypeReply, testXID, NewClientIDOption(ourDUID)), false},
		{"someone else's client ID", reply(MessageTypeReply, testXID, server, NewClientIDOption(theirDUID)), false},
	}
	for _, tt := range tests {
		if got := x.Answers(tt.msg, testXID, ourDUID); got != tt.want {
			t.Errorf("%s: Answers = %v, want %v", tt.name, got, tt.want)
		}
	}
}
