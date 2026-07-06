package microsandbox

import (
	"encoding/json"
	"testing"
)

func TestWithPullProgressSetsCallback(t *testing.T) {
	o := SandboxConfig{}
	if o.onPullProgress != nil {
		t.Fatal("onPullProgress should default to nil")
	}
	var got *PullProgress
	WithPullProgress(func(ev PullProgress) { got = &ev })(&o)
	if o.onPullProgress == nil {
		t.Fatal("WithPullProgress did not set the callback")
	}
	o.onPullProgress(PullProgress{Kind: PullComplete, Reference: "alpine:3.19", LayerCount: 1})
	if got == nil || got.Kind != PullComplete || got.Reference != "alpine:3.19" {
		t.Fatalf("callback not invoked with the expected event: %+v", got)
	}
}

// TestPullProgressDecode asserts the wire JSON emitted by the native FFI layer
// decodes into the public PullProgress fields for each event shape.
func TestPullProgressDecode(t *testing.T) {
	u := func(v uint64) *uint64 { return &v }

	cases := []struct {
		name string
		json string
		want PullProgress
	}{
		{
			name: "resolved with total",
			json: `{"type":"resolved","reference":"alpine:3.19","manifest_digest":"sha256:abc","layer_count":2,"total_download_bytes":1048576}`,
			want: PullProgress{
				Kind: PullResolved, Reference: "alpine:3.19", ManifestDigest: "sha256:abc",
				LayerCount: 2, TotalDownloadBytes: u(1048576),
			},
		},
		{
			name: "layer download progress, total known",
			json: `{"type":"layer_download_progress","layer_index":1,"digest":"sha256:def","downloaded_bytes":512,"total_bytes":2048}`,
			want: PullProgress{
				Kind: PullLayerDownloadProgress, LayerIndex: 1, Digest: "sha256:def",
				DownloadedBytes: 512, TotalBytes: u(2048),
			},
		},
		{
			name: "layer download progress, total unknown",
			json: `{"type":"layer_download_progress","layer_index":0,"digest":"sha256:def","downloaded_bytes":512,"total_bytes":null}`,
			want: PullProgress{
				Kind: PullLayerDownloadProgress, LayerIndex: 0, Digest: "sha256:def",
				DownloadedBytes: 512, TotalBytes: nil,
			},
		},
		{
			name: "materialize progress",
			json: `{"type":"layer_materialize_progress","layer_index":0,"bytes_read":100,"total_bytes":200}`,
			want: PullProgress{
				Kind: PullLayerMaterializeProgress, LayerIndex: 0, BytesRead: 100, TotalBytes: u(200),
			},
		},
		{
			name: "stitch writing fsmeta",
			json: `{"type":"stitch_writing_fsmeta"}`,
			want: PullProgress{Kind: PullStitchWritingFsmeta},
		},
		{
			name: "complete",
			json: `{"type":"complete","reference":"alpine:3.19","layer_count":2}`,
			want: PullProgress{Kind: PullComplete, Reference: "alpine:3.19", LayerCount: 2},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got PullProgress
			if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.Kind != tc.want.Kind || got.Reference != tc.want.Reference ||
				got.ManifestDigest != tc.want.ManifestDigest || got.LayerCount != tc.want.LayerCount ||
				got.LayerIndex != tc.want.LayerIndex || got.Digest != tc.want.Digest ||
				got.DownloadedBytes != tc.want.DownloadedBytes || got.BytesRead != tc.want.BytesRead {
				t.Fatalf("scalar mismatch:\n got %+v\nwant %+v", got, tc.want)
			}
			if !ptrEq(got.TotalBytes, tc.want.TotalBytes) {
				t.Fatalf("TotalBytes mismatch: got %v want %v", deref(got.TotalBytes), deref(tc.want.TotalBytes))
			}
			if !ptrEq(got.TotalDownloadBytes, tc.want.TotalDownloadBytes) {
				t.Fatalf("TotalDownloadBytes mismatch: got %v want %v",
					deref(got.TotalDownloadBytes), deref(tc.want.TotalDownloadBytes))
			}
		})
	}
}

func ptrEq(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func deref(p *uint64) any {
	if p == nil {
		return nil
	}
	return *p
}
