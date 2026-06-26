package tracer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const cgroupPath = "/sys/fs/cgroup"

func cgroupRoot() string {
	if v := strings.TrimSpace(os.Getenv("KTLS_CGROUP_ROOT")); v != "" {
		return v
	}
	return cgroupPath
}

func findCgroupPath() (string, error) {
	var st syscall.Statfs_t
	path := cgroupRoot()
	if err := syscall.Statfs(path, &st); err != nil {
		return "", fmt.Errorf("failed to find cgroup fs at %s: %w", path, err)
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		path = filepath.Join(path, "unified")
	}
	logrus.WithField("component", "ebpf.tracer").Debug("cgroup path: ", path)
	return path, nil
}

// findKTLSCgroupPathsStatic returns baseline cgroup directories for sockops.
func findKTLSCgroupPathsStatic() ([]string, error) {
	root, err := findCgroupPath()
	if err != nil {
		return nil, err
	}
	paths := []string{root}
	for _, p := range discoverKubePodCgroupPaths(root) {
		paths = append(paths, p)
	}
	return paths, nil
}

func discoverKubePodCgroupPaths(root string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	add(filepath.Join(root, "kubepods.slice"))
	add(filepath.Join(root, "kubelet.slice", "kubelet-kubepods.slice"))

	entries, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.Contains(name, "kubepods") {
			add(filepath.Join(root, name))
		}
		add(filepath.Join(root, name, "kubepods.slice"))
		if name == "kubelet.slice" {
			add(filepath.Join(root, name, "kubelet-kubepods.slice"))
			if sub, err := os.ReadDir(filepath.Join(root, name)); err == nil {
				for _, se := range sub {
					if se.IsDir() && strings.Contains(se.Name(), "kubepods") {
						add(filepath.Join(root, name, se.Name()))
					}
				}
			}
		}
	}
	return out
}

func logKTLSCgroupLayout() {
	root := cgroupRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		plog.WithError(err).WithField("root", root).Warn("kTLS cgroup root unreadable")
		return
	}
	dirs := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	kubepods := discoverKubePodCgroupPaths(root)
	plog.WithFields(map[string]interface{}{
		"root":     root,
		"dirs":     dirs,
		"kubepods": kubepods,
	}).Info("kTLS cgroup root layout")
}

// findKTLSCgroupPaths returns cgroup directories for kTLS sockops attachment.
func findKTLSCgroupPaths(scope *PlaintextScope) ([]string, error) {
	if _, err := findKTLSCgroupPathsStatic(); err != nil {
		return nil, err
	}
	return collectKTLSCgroupPaths(scope), nil
}

func collectKTLSCgroupPaths(scope *PlaintextScope) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	workloadNSPIDs := collectKTLSWorkloadCgroupNSPIDs(scope)
	hasIsolatedWorkloads := len(workloadNSPIDs) > 0
	// Host kubepods attach sees sockops_enter but not TCP established for
	// cgroup-namespaced pods; rely on workload namespace attach instead.
	if !hasIsolatedWorkloads {
		for _, p := range findKTLSCgroupPathsStaticOrEmpty() {
			add(p)
		}
	}
	for _, pid := range workloadNSPIDs {
		for _, p := range cgroupPathsForPID(pid) {
			add(p)
		}
	}
	if scope == nil {
		return out
	}
	for _, ip := range scope.peerIPs {
		for pid := range pidsWithIP(ip) {
			if processInIsolatedCgroupNS(pid) {
				continue
			}
			// pause/sandbox holds the pod IP in the host cgroup namespace but
			// its cgroup path is the infra sandbox, not the workload container.
			if hasIsolatedWorkloads {
				continue
			}
			for _, p := range cgroupPathsForPID(pid) {
				add(p)
			}
		}
	}
	for _, n := range scope.peerNets {
		for pid := range pidsWithIPInNet(n) {
			if processInIsolatedCgroupNS(pid) {
				continue
			}
			if hasIsolatedWorkloads {
				continue
			}
			for _, p := range cgroupPathsForPID(pid) {
				add(p)
			}
		}
	}
	return out
}

func findKTLSCgroupPathsStaticOrEmpty() []string {
	paths, err := findKTLSCgroupPathsStatic()
	if err != nil {
		return nil
	}
	return paths
}
