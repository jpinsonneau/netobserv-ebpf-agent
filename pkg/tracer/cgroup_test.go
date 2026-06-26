package tracer

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestProcCgroupRelPath(t *testing.T) {
	proc := t.TempDir()
	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	pidDir := filepath.Join(proc, "1234")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/kubepods.slice/kubepods-burstable.slice/pod.scope\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rel, ok := procCgroupRelPath(1234)
	if !ok {
		t.Fatal("expected cgroup path")
	}
	if rel != "kubepods.slice/kubepods-burstable.slice/pod.scope" {
		t.Fatalf("unexpected rel: %q", rel)
	}
}

func TestCgroupPathsForPID(t *testing.T) {
	root := t.TempDir()
	pod := filepath.Join(root, "kubepods.slice", "pod.scope")
	for _, p := range []string{filepath.Join(root, "kubepods.slice"), pod} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("KTLS_CGROUP_ROOT", root)

	proc := t.TempDir()
	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	pidDir := filepath.Join(proc, "42")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/kubepods.slice/pod.scope\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	paths := cgroupPathsForPID(42)
	if len(paths) != 1 || paths[0] != pod {
		t.Fatalf("expected leaf cgroup path only, got %v", paths)
	}
}

func TestProcCgroupNamespacedRoot(t *testing.T) {
	proc := t.TempDir()
	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	writeCgroup := func(pid int, content string) {
		pidDir := filepath.Join(proc, strconv.Itoa(pid))
		if err := os.MkdirAll(pidDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeCgroup(1, "0::/\n")
	if !procCgroupNamespacedRoot(1) {
		t.Fatal("expected namespaced root cgroup")
	}

	writeCgroup(2, "0::/kubepods.slice/pod.scope\n")
	if procCgroupNamespacedRoot(2) {
		t.Fatal("did not expect namespaced root cgroup")
	}
}

func TestProcessInIsolatedCgroupNS(t *testing.T) {
	proc := t.TempDir()
	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	setup := func(pid int, ns string) {
		pidDir := filepath.Join(proc, strconv.Itoa(pid))
		if err := os.MkdirAll(filepath.Join(pidDir, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ns, filepath.Join(pidDir, "ns", "cgroup")); err != nil {
			t.Fatal(err)
		}
	}

	setup(1, "cgroup:[4026533527]")
	setup(2, "cgroup:[4026534251]")

	if !processInIsolatedCgroupNS(2) {
		t.Fatal("expected isolated cgroup namespace")
	}
	if processInIsolatedCgroupNS(1) {
		t.Fatal("did not expect isolated cgroup namespace for pid 1")
	}
}

func TestCgroupFilesystemPathForPID(t *testing.T) {
	root := t.TempDir()
	pod := filepath.Join(root, "kubepods.slice", "pod.scope")
	if err := os.MkdirAll(pod, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KTLS_CGROUP_ROOT", root)

	proc := t.TempDir()
	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	pidDir := filepath.Join(proc, "42")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/kubepods.slice/pod.scope\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	path, ok := cgroupFilesystemPathForPID(42)
	if !ok || path != pod {
		t.Fatalf("unexpected path: ok=%v path=%q want %q", ok, path, pod)
	}
}

func TestProcCgroupAttachPathNamespacedRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("KTLS_CGROUP_ROOT", root)

	proc := t.TempDir()
	orig := procRootDir
	procRootDir = proc
	t.Cleanup(func() { procRootDir = orig })

	pidDir := filepath.Join(proc, "99")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, ok := procCgroupAttachPath(99)
	if ok {
		t.Fatal("expected no host path for namespaced-root cgroup view")
	}
}
