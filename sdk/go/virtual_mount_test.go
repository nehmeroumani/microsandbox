package microsandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/superradcompany/microsandbox/sdk/go/vfs"
)

// startVirtualMounts must open a listening Unix socket per request, serve the
// provider over it (the VFS hello handshake completes), and clean the socket up
// on Close.
func TestStartVirtualMountsServesAndCleansUp(t *testing.T) {
	reqs := []virtualMountRequest{
		{guestPath: "/data", provider: vfs.ReadOnly{}},
	}
	servers, specs, err := startVirtualMounts(reqs)
	if err != nil {
		t.Fatalf("startVirtualMounts: %v", err)
	}
	t.Cleanup(func() { closeVirtualMounts(servers) })

	if len(specs) != 1 || specs[0].GuestPath != "/data" || specs[0].SocketPath == "" {
		t.Fatalf("unexpected specs: %+v", specs)
	}

	// The runtime side connects and exchanges the 8-byte hello
	// ("MVFS" + u32 big-endian protocol version 1). Drive that exchange to
	// prove the provider is actually being served on the socket.
	conn, err := net.DialTimeout("unix", specs[0].SocketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial provider socket: %v", err)
	}
	defer conn.Close()

	hello := []byte{'M', 'V', 'F', 'S', 0, 0, 0, 1}
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 8)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read server hello: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatalf("server hello = %x, want %x", got, hello)
	}

	// Close tears the listener and socket down.
	closeVirtualMounts(servers)
	if _, err := os.Stat(specs[0].SocketPath); !os.IsNotExist(err) {
		t.Fatalf("socket not cleaned up: stat err = %v", err)
	}
}

// startVirtualMounts must fail fast on configs the Rust builder would reject,
// before creating any temp dir, listener, or serving goroutine.
func TestStartVirtualMountsValidatesBeforeSetup(t *testing.T) {
	cases := []struct {
		name string
		reqs []virtualMountRequest
	}{
		{"nil provider", []virtualMountRequest{{guestPath: "/data"}}},
		{"relative path", []virtualMountRequest{{guestPath: "data", provider: vfs.ReadOnly{}}}},
		{"guest root", []virtualMountRequest{{guestPath: "/", provider: vfs.ReadOnly{}}}},
		{"separator in path", []virtualMountRequest{{guestPath: "/da:ta", provider: vfs.ReadOnly{}}}},
		{"duplicate paths", []virtualMountRequest{
			{guestPath: "/data", provider: vfs.ReadOnly{}},
			{guestPath: "/data", provider: vfs.ReadOnly{}},
		}},
	}
	for _, c := range cases {
		servers, specs, err := startVirtualMounts(c.reqs)
		var e *Error
		if !errors.As(err, &e) || e.Kind != ErrInvalidConfig {
			t.Errorf("%s: err = %v, want *Error{Kind: ErrInvalidConfig}", c.name, err)
		}
		if servers != nil || specs != nil {
			t.Errorf("%s: expected no servers/specs on validation failure", c.name)
		}
	}
}

// CreateSandbox must reject the WithDetached+WithVirtualMount combination
// before any FFI call: the provider dies with this process, so a detached VM
// would be left with a dead mount.
func TestCreateRejectsDetachedVirtualMounts(t *testing.T) {
	_, err := CreateSandbox(context.Background(), "vfs-detached",
		WithDetached(),
		WithVirtualMount("/data", vfs.ReadOnly{}),
	)
	var e *Error
	if !errors.As(err, &e) || e.Kind != ErrInvalidConfig {
		t.Fatalf("CreateSandbox detached+virtual mount = %v, want *Error{Kind: ErrInvalidConfig}", err)
	}
}

// Detach must refuse a sandbox that owns virtual mounts (the provider runs in
// this process) and must not touch the Rust handle while doing so.
func TestDetachRejectsVirtualMounts(t *testing.T) {
	s := &Sandbox{vfsServers: []*vfsMountServer{{}}}
	if err := s.Detach(context.Background()); !errors.Is(err, ErrVirtualMountDetach) {
		t.Fatalf("Detach with virtual mounts = %v, want ErrVirtualMountDetach", err)
	}
}

// buildFFICreateOptions stays pure: with no virtual mounts the envelope carries
// none, and the resolved specs are injected by CreateSandbox, not the builder.
func TestBuildFFICreateOptionsHasNoVirtualMountsByDefault(t *testing.T) {
	opts := buildFFICreateOptions(SandboxConfig{})
	if opts.VirtualMounts != nil {
		t.Fatalf("expected no virtual mounts, got %+v", opts.VirtualMounts)
	}
}
