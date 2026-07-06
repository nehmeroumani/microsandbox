package microsandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
	"github.com/superradcompany/microsandbox/sdk/go/vfs"
)

// ErrVirtualMountDetach is returned by [Sandbox.Detach] when the sandbox has
// active virtual mounts. A virtual mount's provider runs in this process, so
// detaching — which is meant to leave the VM running after this process may
// exit — would strand the mount: the host listener, socket dir, and serving
// goroutines would either leak or be torn down out from under the live VM.
// Close the sandbox instead.
var ErrVirtualMountDetach = errors.New("microsandbox: cannot detach a sandbox with active virtual mounts")

// virtualMountRequest is a programmable VFS mount registered via WithVirtualMount.
type virtualMountRequest struct {
	guestPath string
	provider  vfs.PathFs
}

// WithVirtualMount mounts a programmable filesystem at guestPath inside the
// sandbox, served by provider.
//
// The SDK hosts provider on a host Unix-domain socket for the sandbox's
// lifetime; the runtime connects to that socket at boot and serves it as a
// virtio-fs share, speaking the VFS RPC protocol. Implement [vfs.PathFs] (embed
// [vfs.ReadOnly] for ENOSYS defaults) to back the filesystem with anything —
// an in-memory map, a database, an object store, or a remote API.
//
// Because provider runs in this process, the mount is only valid while the
// returned [Sandbox] is open: it is torn down by [Sandbox.Close]. Virtual
// mounts are therefore not usable with detached sandboxes, whose VM outlives
// this process: combining WithVirtualMount with WithDetached is rejected by
// [CreateSandbox] with [ErrInvalidConfig], and [Sandbox.Detach] returns
// [ErrVirtualMountDetach].
func WithVirtualMount(guestPath string, provider vfs.PathFs) SandboxOption {
	return func(o *SandboxConfig) {
		o.virtualMounts = append(o.virtualMounts, virtualMountRequest{
			guestPath: guestPath,
			provider:  provider,
		})
	}
}

// vfsMountServer hosts one provider on a Unix-domain socket until Close.
type vfsMountServer struct {
	listener  net.Listener
	dir       string
	closeOnce sync.Once
}

// Close stops accepting connections and removes the socket directory. Safe to
// call multiple times.
func (s *vfsMountServer) Close() error {
	s.closeOnce.Do(func() {
		_ = s.listener.Close()
		_ = os.RemoveAll(s.dir)
	})
	return nil
}

// validateVirtualMounts fail-fasts on requests the Rust builder would reject
// anyway (see validate_volume_mounts in the Rust SDK), so no temp dirs,
// listeners, or serving goroutines are ever created for an invalid config.
func validateVirtualMounts(reqs []virtualMountRequest) error {
	invalid := func(format string, args ...any) error {
		return &Error{Kind: ErrInvalidConfig, Message: fmt.Sprintf(format, args...)}
	}
	seen := make(map[string]struct{}, len(reqs))
	for _, req := range reqs {
		if req.provider == nil {
			return invalid("virtual mount %q: provider must not be nil", req.guestPath)
		}
		if !strings.HasPrefix(req.guestPath, "/") {
			return invalid("virtual mount guest path must be absolute: %q", req.guestPath)
		}
		if req.guestPath == "/" {
			return invalid("cannot mount a virtual filesystem at guest root /")
		}
		if strings.ContainsAny(req.guestPath, ":;,") {
			return invalid("virtual mount guest path must not contain ':', ';', or ',': %q", req.guestPath)
		}
		if _, dup := seen[req.guestPath]; dup {
			return invalid("multiple mounts cannot share the same guest path: %s", req.guestPath)
		}
		seen[req.guestPath] = struct{}{}
	}
	return nil
}

// startVirtualMounts opens a Unix-socket listener per request, serves each
// provider in the background, and returns the started servers together with the
// resolved (guest_path, socket_path) pairs for the FFI. On any error it tears
// down everything already started so no listener or socket leaks.
func startVirtualMounts(reqs []virtualMountRequest) ([]*vfsMountServer, []ffi.VirtualMountSpec, error) {
	if len(reqs) == 0 {
		return nil, nil, nil
	}
	if err := validateVirtualMounts(reqs); err != nil {
		return nil, nil, err
	}
	servers := make([]*vfsMountServer, 0, len(reqs))
	specs := make([]ffi.VirtualMountSpec, 0, len(reqs))
	for _, req := range reqs {
		dir, err := os.MkdirTemp("", "msb-vfs-")
		if err != nil {
			closeVirtualMounts(servers)
			return nil, nil, fmt.Errorf("virtual mount %q: %w", req.guestPath, err)
		}
		// A short, fixed socket name under a private dir keeps the path well
		// under the ~104-byte sun_path limit while staying unique per mount.
		sockPath := filepath.Join(dir, "vfs.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			_ = os.RemoveAll(dir)
			closeVirtualMounts(servers)
			return nil, nil, fmt.Errorf("virtual mount %q: listen: %w", req.guestPath, err)
		}
		srv := &vfsMountServer{listener: ln, dir: dir}
		servers = append(servers, srv)
		specs = append(specs, ffi.VirtualMountSpec{
			GuestPath:  req.guestPath,
			SocketPath: sockPath,
		})
		go serveVirtualMount(ln, req.provider)
	}
	return servers, specs, nil
}

// serveVirtualMount accepts connections on ln and serves each with vfs.Serve
// until the listener is closed. The runtime opens one connection per mount, but
// the loop tolerates reconnects.
func serveVirtualMount(ln net.Listener, provider vfs.PathFs) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed by Close
		}
		go func() {
			defer conn.Close()
			_ = vfs.Serve(conn, provider)
		}()
	}
}

func closeVirtualMounts(servers []*vfsMountServer) {
	for _, s := range servers {
		_ = s.Close()
	}
}
