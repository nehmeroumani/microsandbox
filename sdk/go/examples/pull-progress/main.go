// Image-pull progress example for the microsandbox Go SDK.
//
// Demonstrates WithPullProgress: a callback that receives per-layer download
// and EROFS-materialization events while the sandbox's image is pulled during
// CreateSandbox. Progress is only reported when the image is not already
// cached locally, so this removes any cached copy first to force a fresh pull.
//
// Build: from sdk/go, run
//
//	go run ./examples/pull-progress
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

const image = "alpine:3.19"

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := microsandbox.EnsureInstalled(ctx); err != nil {
		log.Fatalf("EnsureInstalled: %v", err)
	}

	// Force a fresh pull so progress events are emitted (cached images skip the
	// download entirely). Ignore "not found" — the image may not be cached yet.
	if err := microsandbox.Image.Remove(ctx, image, true); err != nil {
		log.Printf("(ignoring) Image.Remove %s: %v", image, err)
	}

	name := fmt.Sprintf("go-sdk-pull-progress-%d", time.Now().Unix())
	log.Printf("creating sandbox %q (%s) with pull progress", name, image)

	progress := func(ev microsandbox.PullProgress) {
		switch ev.Kind {
		case microsandbox.PullResolving:
			fmt.Printf("  resolving %s…\n", ev.Reference)
		case microsandbox.PullResolved:
			fmt.Printf("  resolved: %d layer(s), %s to download\n",
				ev.LayerCount, humanBytesPtr(ev.TotalDownloadBytes))
		case microsandbox.PullLayerDownloadProgress:
			fmt.Printf("  layer %d  download  %s / %s\n",
				ev.LayerIndex, humanBytes(ev.DownloadedBytes), humanBytesPtr(ev.TotalBytes))
		case microsandbox.PullLayerDownloadComplete:
			fmt.Printf("  layer %d  downloaded (%s)\n", ev.LayerIndex, humanBytes(ev.DownloadedBytes))
		case microsandbox.PullLayerMaterializeProgress:
			fmt.Printf("  layer %d  extract   %s / %s\n",
				ev.LayerIndex, humanBytes(ev.BytesRead), humanBytesPtr(ev.TotalBytes))
		case microsandbox.PullLayerMaterializeComplete:
			fmt.Printf("  layer %d  extracted\n", ev.LayerIndex)
		case microsandbox.PullComplete:
			fmt.Printf("  pull complete: %s (%d layers)\n", ev.Reference, ev.LayerCount)
		default:
			// Other phases (verifying, stitching, …) — print the bare phase.
			fmt.Printf("  %s\n", ev.Kind)
		}
	}

	start := time.Now()
	sb, err := microsandbox.CreateSandbox(ctx, name,
		microsandbox.WithImage(image),
		microsandbox.WithMemory(256),
		microsandbox.WithCPUs(1),
		microsandbox.WithPullProgress(progress),
	)
	if err != nil {
		log.Fatalf("CreateSandbox: %v", err)
	}
	defer func() {
		stopCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
		defer c()
		if err := sb.Stop(stopCtx); err != nil {
			log.Printf("Stop: %v", err)
		}
		if err := sb.Close(); err != nil {
			log.Printf("Close: %v", err)
		}
		if err := microsandbox.RemoveSandbox(context.Background(), name); err != nil {
			log.Printf("RemoveSandbox: %v", err)
		}
	}()

	fmt.Printf("sandbox up in %s\n", time.Since(start).Round(time.Millisecond))

	out, err := sb.Exec(ctx, "echo", []string{"pull-progress example OK"})
	if err != nil {
		log.Fatalf("Exec: %v", err)
	}
	fmt.Printf("guest says: %s", out.Stdout())
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanBytesPtr(n *uint64) string {
	if n == nil {
		return "?"
	}
	return humanBytes(*n)
}
