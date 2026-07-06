// Programmable virtual-filesystem example for the microsandbox Go SDK.
//
// Exercises: WithVirtualMount — a filesystem implemented in Go (here a tiny
// in-memory tree) is mounted inside the sandbox at /data. Reads and writes the
// guest performs are served by the Go provider in this process, so writes the
// guest makes show up in the provider's map and vice versa.
//
// This needs a working runtime, so run it on a host where the sandbox can boot.
// From the repo root:
//
//	just go-run virtual-mount
//
// (which builds the local FFI cdylib and runs with -tags microsandbox_ffi_path)
package main

import (
	"context"
	"fmt"
	"log"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
	"github.com/superradcompany/microsandbox/sdk/go/vfs"
)

//--------------------------------------------------------------------------------------------------
// A tiny in-memory filesystem provider
//--------------------------------------------------------------------------------------------------

// memFS is a minimal read/write filesystem held entirely in a Go map. Embedding
// vfs.ReadOnly supplies ENOSYS/no-op defaults for everything we don't override.
type memFS struct {
	vfs.ReadOnly
	mu    sync.Mutex
	files map[string][]byte
}

func newMemFS() *memFS {
	return &memFS{files: map[string][]byte{
		"/hello.txt": []byte("hello from the Go provider\n"),
	}}
}

func (f *memFS) GetAttr(p []byte) (vfs.Attr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if string(p) == "/" {
		return vfs.DirAttr(0o755), nil
	}
	data, ok := f.files[string(p)]
	if !ok {
		return vfs.Attr{}, vfs.ENOENT
	}
	return vfs.FileAttr(0o644, uint64(len(data))), nil
}

func (f *memFS) ReadDir(p []byte) ([]vfs.DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if string(p) != "/" {
		return nil, vfs.ENOTDIR
	}
	var out []vfs.DirEntry
	for fp := range f.files {
		out = append(out, vfs.DirEntry{Name: []byte(path.Base(fp)), Kind: vfs.File})
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].Name) < string(out[j].Name) })
	return out, nil
}

func (f *memFS) Read(p []byte, offset uint64, size uint32) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[string(p)]
	if !ok {
		return nil, vfs.ENOENT
	}
	if offset >= uint64(len(data)) {
		return nil, nil // EOF
	}
	end := min(offset+uint64(size), uint64(len(data)))
	return append([]byte(nil), data[offset:end]...), nil
}

func (f *memFS) Create(p []byte, _ vfs.Attr) (vfs.Attr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[string(p)] = nil
	return vfs.FileAttr(0o644, 0), nil
}

func (f *memFS) Write(p []byte, offset uint64, data []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur := f.files[string(p)]
	end := int(offset) + len(data)
	if end > len(cur) {
		cur = append(cur, make([]byte, end-len(cur))...)
	}
	copy(cur[offset:], data)
	f.files[string(p)] = cur
	return len(data), nil
}

func (f *memFS) snapshot(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.files[name])
}

//--------------------------------------------------------------------------------------------------
// Driver
//--------------------------------------------------------------------------------------------------

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	provider := newMemFS()
	name := fmt.Sprintf("go-sdk-vfs-%d", time.Now().Unix())
	log.Printf("creating sandbox %q with a Go-backed filesystem at /data", name)

	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage("alpine:3.19"),
		microsandbox.WithMemory(256),
		microsandbox.WithVirtualMount("/data", provider),
	)
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		_ = sb.Stop(stopCtx)
		_ = sb.Close() // tears down the provider's socket server
		_ = microsandbox.RemoveSandbox(context.Background(), name)
	}()

	// 1. The guest sees the file the provider pre-populated.
	out, err := sb.Exec(ctx, "cat", []string{"/data/hello.txt"})
	must("cat /data/hello.txt", err)
	if !out.Success() || !strings.Contains(out.Stdout(), "hello from the Go provider") {
		log.Fatalf("read-through failed: %q (exit %d)", out.Stdout(), out.ExitCode())
	}
	fmt.Printf("  guest read provider file: %q\n", strings.TrimSpace(out.Stdout()))

	// 2. The guest lists the provider's directory.
	out, err = sb.Exec(ctx, "ls", []string{"/data"})
	must("ls /data", err)
	fmt.Printf("  guest ls /data: %q\n", strings.TrimSpace(out.Stdout()))

	// 3. The guest writes a file; the write lands in the Go provider's map.
	out, err = sb.Shell(ctx, "echo 'written by the guest' > /data/from-guest.txt")
	must("guest write", err)
	if !out.Success() {
		log.Fatalf("guest write failed (exit %d): %q", out.ExitCode(), out.Stderr())
	}
	if got := provider.snapshot("/from-guest.txt"); !strings.Contains(got, "written by the guest") {
		log.Fatalf("write did not reach the Go provider; provider has %q", got)
	}
	fmt.Printf("  guest write reached the Go provider: %q\n",
		strings.TrimSpace(provider.snapshot("/from-guest.txt")))

	fmt.Println("OK — programmable virtual mount works end to end")
}

func must(label string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", label, err)
	}
}
