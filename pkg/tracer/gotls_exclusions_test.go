package tracer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsGoTLSExcluded(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		comm     string
		excluded bool
	}{
		{
			name:     "kubelet by path",
			path:     "/usr/bin/kubelet",
			comm:     "kubelet",
			excluded: true,
		},
		{
			name:     "kubelet deleted binary suffix",
			path:     "/usr/bin/kubelet (deleted)",
			comm:     "kubelet",
			excluded: true,
		},
		{
			name:     "kubelet by comm only",
			path:     "/proc/1234/exe",
			comm:     "kubelet",
			excluded: true,
		},
		{
			name:     "ovnkube truncated comm",
			path:     "/usr/bin/ovnkube-node",
			comm:     "ovnkube-node",
			excluded: true,
		},
		{
			name:     "openshift host binary",
			path:     "/usr/bin/openshift-kube-apiserver",
			comm:     "openshift-k",
			excluded: true,
		},
		{
			name:     "kubelet data dir",
			path:     "/var/lib/kubelet/pods/abc/volumes/bin/kubelet",
			comm:     "",
			excluded: true,
		},
		{
			name:     "container app path",
			path:     "/app/server",
			comm:     "server",
			excluded: false,
		},
		{
			name:     "usr local workload",
			path:     "/usr/local/bin/my-service",
			comm:     "my-service",
			excluded: false,
		},
		{
			name:     "crio",
			path:     "/usr/bin/crio",
			comm:     "crio",
			excluded: true,
		},
		{
			name:     "multus by comm",
			path:     "/usr/bin/kube-multus",
			comm:     "kube-multus",
			excluded: true,
		},
		{
			name:     "console by comm",
			path:     "/opt/console/bin/console",
			comm:     "console",
			excluded: true,
		},
		{
			name:     "network metrics truncated comm",
			path:     "/usr/bin/network-metrics-daemon",
			comm:     "network-metrics-d",
			excluded: true,
		},
		{
			name:     "coredns",
			path:     "/coredns",
			comm:     "coredns",
			excluded: true,
		},
		{
			name:     "konnectivity truncated comm",
			path:     "/usr/bin/konnectivity-agent",
			comm:     "konnectivity-age",
			excluded: true,
		},
		{
			name:     "kube-rbac-proxy sidecar",
			path:     "/usr/bin/kube-rbac-proxy",
			comm:     "kube-rbac-proxy",
			excluded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGoTLSExcluded(tt.path, tt.comm)
			if got != tt.excluded {
				t.Fatalf("isGoTLSExcluded(%q, %q) = %v, want %v", tt.path, tt.comm, got, tt.excluded)
			}
		})
	}
}

func TestResolveProcExe(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pid := "4242"
	pidDir := filepath.Join(proc, pid)
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "usr", "bin", "kubelet")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte{0}, 0o644); err != nil {
		t.Fatal(err)
	}
	exePath := filepath.Join(pidDir, "exe")
	if err := os.Symlink(target, exePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("kubelet"), 0o644); err != nil {
		t.Fatal(err)
	}

	origProc := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = origProc })

	resolved, comm := resolveProcExe(pid, exePath)
	if comm != "kubelet" {
		t.Fatalf("comm = %q, want kubelet", comm)
	}
	if resolved != target {
		t.Fatalf("resolved = %q, want %q", resolved, target)
	}
}

func TestDiscoverGoTLSPathsSkipsExcluded(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")

	writeProcEntry(t, proc, "1000", "kubelet", exe)
	writeProcEntry(t, proc, "2000", "myapp", exe)

	origProc := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = origProc })

	attacher := &gotlsAttacher{cfg: &FlowFetcherConfig{}}
	paths := attacher.discoverPaths()

	if len(paths) != 1 {
		t.Fatalf("expected 1 discovered path, got %v", paths)
	}
	want := filepath.Join(proc, "2000", "exe")
	if paths[0] != want {
		t.Fatalf("expected %q, got %q", want, paths[0])
	}
}

func TestPlaintextCaptureExcludedPIDPeerScoped(t *testing.T) {
	tmp := t.TempDir()
	proc := filepath.Join(tmp, "proc")
	pid := "3000"
	writeProcEntry(t, proc, pid, "console", filepath.Join(tmp, "console"))

	origProc := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = origProc })

	scope := &PlaintextScope{
		pidScopeActive: true,
		allowedPIDs:    map[int]struct{}{3000: {}},
	}

	if !isPlaintextCaptureExcludedPID(pid, nil) {
		t.Fatal("console should be soft-excluded without peer scope")
	}
	if isPlaintextCaptureExcludedPID(pid, scope) {
		t.Fatal("console should be allowed when peer_ip scoped to this PID")
	}

	kubeletPID := "1000"
	writeProcEntry(t, proc, kubeletPID, "kubelet", filepath.Join(tmp, "kubelet"))
	scope.allowedPIDs[1000] = struct{}{}
	if !isPlaintextCaptureExcludedPID(kubeletPID, scope) {
		t.Fatal("kubelet must stay hard-denied even when peer_ip scoped")
	}
}

func writeProcEntry(t *testing.T, proc, pid, comm, exeTarget string) {
	t.Helper()
	pidDir := filepath.Join(proc, pid)
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte(comm), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exeTarget, filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
}
