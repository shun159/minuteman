package pollfd

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// udp opens a loopback UDP socket the raw way, and returns it with its
// address.
func udp(t *testing.T) (*FD, *unix.SockaddrInet4) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(fd, "udp")
	if err != nil {
		t.Fatal(err)
	}
	return p, sa.(*unix.SockaddrInet4)
}

func TestSendRecv(t *testing.T) {
	a, _ := udp(t)
	defer a.Close()
	b, addr := udp(t)
	defer b.Close()
	if err := a.Sendto([]byte("hello"), addr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _, err := b.Recvfrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Errorf("Recvfrom = %q, %v", buf[:n], err)
	}
}

// Closing the socket wakes a read waiting on it, with nothing to read.
func TestCloseWakesRecv(t *testing.T) {
	p, _ := udp(t)
	done := make(chan error, 1)
	go func() {
		_, _, err := p.Recvfrom(make([]byte, 16))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // let it park
	p.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Recvfrom after Close succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake Recvfrom")
	}
}
