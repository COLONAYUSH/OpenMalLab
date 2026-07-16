// the jail: how every hostile-input container runs. one recipe, expressed
// once as engine api fields, pinned by TestJailRecipePinsTheBoundaryProof to
// the flags in deploy/proof/boundary-proof.sh, and proven live by that script.
//
// the properties: no network (only loopback, no routes), all capabilities
// dropped, no privilege escalation, the engine's builtin seccomp profile
// (never unconfined), read-only rootfs, a small noexec scratch tmpfs, nobody
// (65534), hard memory/cpu/pid caps, private cgroup and ipc namespaces, no
// log driver (we capture the attached stream, bounded, ourselves), and no
// environment beyond PATH. exactly one mount when scanning: the sample,
// read-only, one file via volume-subpath.
package main

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	// jailLabel marks every container this process spawns, so leaked ones can
	// be swept on boot after a crash.
	jailLabel = "com.openmallab.jailed"

	// maxJailOutputBytes caps what we are willing to hold of a jail's stdout.
	// mirrors the broker's input cap: anything past it is a violation, not data.
	maxJailOutputBytes = 1 << 20
	// stderr is ops signal only; a small bounded preview is plenty.
	maxJailStderrBytes = 4096
)

func jailedHostConfig() *container.HostConfig {
	pids := int64(128)
	return &container.HostConfig{
		NetworkMode:    "none",
		CapDrop:        strslice.StrSlice{"ALL"},
		SecurityOpt:    []string{"no-new-privileges", "seccomp=builtin"},
		ReadonlyRootfs: true,
		Tmpfs: map[string]string{
			"/scratch": "rw,noexec,nosuid,nodev,size=64m",
		},
		LogConfig: container.LogConfig{Type: "none"},
		Resources: container.Resources{
			Memory:     512 << 20,
			MemorySwap: 512 << 20, // equal to memory: zero swap headroom
			NanoCPUs:   1_000_000_000,
			PidsLimit:  &pids,
		},
		CgroupnsMode: container.CgroupnsMode("private"),
		IpcMode:      container.IpcMode("private"),
	}
}

// jailedConfig carries nothing into the jail: no environment (docker injects
// only the image's PATH), no credentials, just the label that lets the reaper
// find leaks.
func jailedConfig(image string) *container.Config {
	return &container.Config{
		Image:  image,
		User:   "65534:65534",
		Env:    []string{},
		Labels: map[string]string{jailLabel: "1"},
	}
}

// sampleMount mounts exactly one content-addressed file read-only at
// /in/sample via volume-subpath. the worker sees one file, never the vault.
func sampleMount(volume, sha string) mount.Mount {
	return mount.Mount{
		Type:     mount.TypeVolume,
		Source:   volume,
		Target:   "/in/sample",
		ReadOnly: true,
		VolumeOptions: &mount.VolumeOptions{
			Subpath: sha,
		},
	}
}

// cappedBuffer keeps the first max bytes, flags anything beyond, and always
// reports the full write so the stream drains instead of stalling the jail.
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.truncated = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}

type jailSpec struct {
	image        string
	mounts       []mount.Mount
	stdin        []byte // nil means no stdin at all
	wallClock    time.Duration
	submissionID string // audit label only
}

type jailResult struct {
	stdout          []byte
	stderr          []byte
	exitCode        int64
	stdoutTruncated bool
}

// runJailed runs one single-use jailed container to completion: create,
// attach, start, feed stdin if any, capture bounded stdout/stderr, enforce
// the wall clock with a hard kill, and always remove the container. the
// bytes it returns are UNTRUSTED unless they came out of the broker.
func runJailed(ctx context.Context, docker *client.Client, spec jailSpec) (*jailResult, error) {
	cfg := jailedConfig(spec.image)
	if spec.stdin != nil {
		cfg.OpenStdin = true
		cfg.StdinOnce = true
	}
	if spec.submissionID != "" {
		cfg.Labels["com.openmallab.submission"] = spec.submissionID
	}
	hc := jailedHostConfig()
	hc.Mounts = spec.mounts

	created, err := docker.ContainerCreate(ctx, cfg, hc, &network.NetworkingConfig{}, nil, "")
	if err != nil {
		return nil, fmt.Errorf("jail create: %w", err)
	}
	id := created.ID
	defer func() {
		// single-use: the jail is always removed, whatever happened above.
		rmCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = docker.ContainerRemove(rmCtx, id, container.RemoveOptions{Force: true})
	}()

	// attach before start so no early output is lost.
	attach, err := docker.ContainerAttach(ctx, id, container.AttachOptions{
		Stream: true,
		Stdin:  spec.stdin != nil,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("jail attach: %w", err)
	}
	defer attach.Close()

	if err := docker.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("jail start: %w", err)
	}

	if spec.stdin != nil {
		go func() {
			_, _ = attach.Conn.Write(spec.stdin)
			_ = attach.CloseWrite() // half-close: the jail sees eof
		}()
	}

	stdout := &cappedBuffer{max: maxJailOutputBytes}
	stderr := &cappedBuffer{max: maxJailStderrBytes}
	copyDone := make(chan error, 1)
	go func() {
		// demux the attach stream; capped writers keep it draining forever
		// without holding more than the caps.
		_, cErr := stdcopy.StdCopy(stdout, stderr, attach.Reader)
		copyDone <- cErr
	}()

	// the supervisor wall clock. the jail gets killed, not reasoned with.
	wallCtx, cancel := context.WithTimeout(ctx, spec.wallClock)
	defer cancel()
	statusCh, errCh := docker.ContainerWait(wallCtx, id, container.WaitConditionNotRunning)

	var exit int64
	select {
	case st := <-statusCh:
		exit = st.StatusCode
	case werr := <-errCh:
		if wallCtx.Err() != nil {
			killCtx, kcancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer kcancel()
			_ = docker.ContainerKill(killCtx, id, "KILL")
			return nil, fmt.Errorf("jail exceeded wall clock %s and was killed", spec.wallClock)
		}
		return nil, fmt.Errorf("jail wait: %w", werr)
	}

	// jail exited: let the stream drain to eof, bounded.
	select {
	case <-copyDone:
	case <-time.After(10 * time.Second):
	}

	return &jailResult{
		stdout:          stdout.buf.Bytes(),
		stderr:          stderr.buf.Bytes(),
		exitCode:        exit,
		stdoutTruncated: stdout.truncated,
	}, nil
}

// reapLeakedJails removes any jailed container left behind by a crash. jails
// are single-use and always removed after their run; anything still carrying
// the label at boot is garbage by definition.
func reapLeakedJails(ctx context.Context, docker *client.Client) int {
	f := filters.NewArgs(filters.Arg("label", jailLabel+"=1"))
	list, err := docker.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range list {
		if err := docker.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true}); err == nil {
			n++
		}
	}
	return n
}

// sanitizeForLog neutralizes hostile bytes before they touch a log line:
// bounded length, printable ascii only. worker stderr is attacker-influenced;
// it never gets to forge log records or drive a terminal.
func sanitizeForLog(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			out[i] = '.'
		} else {
			out[i] = c
		}
	}
	return string(out)
}
