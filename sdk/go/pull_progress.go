package microsandbox

import (
	"context"
	"encoding/json"

	"github.com/superradcompany/microsandbox/sdk/go/internal/ffi"
)

// PullProgressKind identifies the phase reported by a PullProgress event.
type PullProgressKind string

const (
	// PullResolving is emitted while the image reference is being resolved.
	PullResolving PullProgressKind = "resolving"
	// PullResolved is emitted once the manifest is parsed; layer count and
	// total download size are now known.
	PullResolved PullProgressKind = "resolved"
	// PullLayerDownloadProgress reports byte-level download progress for a layer.
	PullLayerDownloadProgress PullProgressKind = "layer_download_progress"
	// PullLayerDownloadComplete is emitted when a layer download finishes.
	PullLayerDownloadComplete PullProgressKind = "layer_download_complete"
	// PullLayerDownloadVerifying is emitted while a downloaded blob is verified.
	PullLayerDownloadVerifying PullProgressKind = "layer_download_verifying"
	// PullLayerMaterializeStarted is emitted when EROFS materialization begins.
	PullLayerMaterializeStarted PullProgressKind = "layer_materialize_started"
	// PullLayerMaterializeProgress reports byte-level materialization progress.
	PullLayerMaterializeProgress PullProgressKind = "layer_materialize_progress"
	// PullLayerMaterializeWriting is emitted while the EROFS image is written.
	PullLayerMaterializeWriting PullProgressKind = "layer_materialize_writing"
	// PullLayerMaterializeComplete is emitted when a layer's EROFS is done.
	PullLayerMaterializeComplete PullProgressKind = "layer_materialize_complete"
	// PullStitchMergingTrees is emitted while per-layer trees are merged.
	PullStitchMergingTrees PullProgressKind = "stitch_merging_trees"
	// PullStitchWritingFsmeta is emitted while the merged metadata EROFS is written.
	PullStitchWritingFsmeta PullProgressKind = "stitch_writing_fsmeta"
	// PullStitchWritingVMDK is emitted while the VMDK descriptor is written.
	PullStitchWritingVMDK PullProgressKind = "stitch_writing_vmdk"
	// PullStitchComplete is emitted when stitching finishes.
	PullStitchComplete PullProgressKind = "stitch_complete"
	// PullComplete is emitted when the entire image pull is done.
	PullComplete PullProgressKind = "complete"
)

// PullProgress is a single image-pull progress event delivered to the callback
// registered with WithPullProgress. Which fields are populated depends on Kind.
type PullProgress struct {
	// Kind is the event phase.
	Kind PullProgressKind `json:"type"`

	// Reference is the image reference (Resolving, Resolved, Complete).
	Reference string `json:"reference,omitempty"`
	// ManifestDigest is the resolved manifest digest (Resolved).
	ManifestDigest string `json:"manifest_digest,omitempty"`
	// LayerCount is the number of layers (Resolved, StitchMergingTrees, Complete).
	LayerCount int `json:"layer_count,omitempty"`
	// TotalDownloadBytes is the sum of compressed layer sizes, when the manifest
	// reports them (Resolved). Nil when sizes are unknown.
	TotalDownloadBytes *uint64 `json:"total_download_bytes,omitempty"`

	// LayerIndex is the 0-based index of the layer for per-layer events.
	LayerIndex int `json:"layer_index,omitempty"`
	// Digest is the layer blob digest (download events).
	Digest string `json:"digest,omitempty"`
	// DiffID is the layer diff ID (materialize events).
	DiffID string `json:"diff_id,omitempty"`
	// DownloadedBytes is bytes downloaded so far for the layer (download events).
	DownloadedBytes uint64 `json:"downloaded_bytes,omitempty"`
	// BytesRead is bytes read so far while materializing the layer.
	BytesRead uint64 `json:"bytes_read,omitempty"`
	// TotalBytes is the layer's total byte size. For downloads it is nil when
	// the manifest omits sizes; for materialization it is always set.
	TotalBytes *uint64 `json:"total_bytes,omitempty"`
}

// PullProgressFunc receives image-pull progress events while a sandbox boots.
// It is invoked synchronously from the goroutine calling CreateSandbox, in
// event order; keep it fast and non-blocking and do not call back into the
// sandbox from within it.
type PullProgressFunc func(PullProgress)

// WithPullProgress registers a callback invoked with per-layer image download
// and materialization progress as the sandbox's image is pulled during
// CreateSandbox. It has no effect when the image is already cached locally (no
// pull happens) or on cloud backends (image pulls run server-side).
func WithPullProgress(fn PullProgressFunc) SandboxOption {
	return func(o *SandboxConfig) { o.onPullProgress = fn }
}

// createWithPullProgress drives the streaming create FFI, forwarding decoded
// progress events to cb, and returns the booted sandbox handle.
func createWithPullProgress(
	ctx context.Context,
	name string,
	ffiOpts ffi.CreateOptions,
	cb PullProgressFunc,
) (*ffi.Sandbox, error) {
	stream, err := ffi.CreateSandboxWithProgress(ctx, name, ffiOpts)
	if err != nil {
		return nil, wrapFFI(err)
	}
	for {
		raw, done, rerr := stream.Recv(ctx)
		if rerr != nil {
			_ = stream.Close()
			return nil, wrapFFI(rerr)
		}
		if done {
			break
		}
		if cb != nil {
			var ev PullProgress
			if json.Unmarshal(raw, &ev) == nil {
				cb(ev)
			}
		}
	}
	inner, err := stream.Result(ctx)
	if err != nil {
		_ = stream.Close()
		return nil, wrapFFI(err)
	}
	return inner, nil
}
