package tracer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	hostCgroupNSPath = "/proc/1/ns/cgroup"
	hostMountNSPath  = "/proc/1/ns/mnt"
)

func cgroupFilesystemPathForPID(pid int) (string, bool) {
	return cgroupHostFilesystemPathForPID(pid)
}

// cgroupHostFilesystemPathForPID resolves the physical cgroup directory from the
// agent/host cgroup namespace view. Required before entering a workload cgroup
// namespace: inside that namespace /proc/pid/cgroup shows 0::/ but BPF attach
// still needs the host-visible path (e.g. .../cri-containerd-*.scope).
func cgroupHostFilesystemPathForPID(pid int) (string, bool) {
	rel, ok := procCgroupRelPath(pid)
	if !ok || rel == "" {
		return "", false
	}
	return filepath.Join(cgroupRoot(), rel), true
}

func procCgroupAttachPath(pid int) (string, bool) {
	return cgroupHostFilesystemPathForPID(pid)
}

func attachCgroupSockopsAtPath(path string, prog *cilium.Program) (link.Link, error) {
	if path == "" {
		return nil, fmt.Errorf("empty cgroup path")
	}
	return link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Program: prog,
		Attach:  cilium.AttachCGroupSockOps,
	})
}

type nsRestore struct {
	restore func()
}

func (n nsRestore) Close() {
	if n.restore != nil {
		n.restore()
	}
}

// enterAttachNamespaces switches mount and cgroup namespaces for BPF cgroup attach.
// Host mount namespace ensures /host-cgroup paths resolve like on the node.
func enterAttachNamespaces(mountNSPath, cgroupNSPath string) (nsRestore, error) {
	selfMnt, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		return nsRestore{}, fmt.Errorf("opening self mount namespace: %w", err)
	}
	defer selfMnt.Close()

	selfCgroup, err := os.Open("/proc/self/ns/cgroup")
	if err != nil {
		return nsRestore{}, fmt.Errorf("opening self cgroup namespace: %w", err)
	}
	defer selfCgroup.Close()

	if mountNSPath != "" {
		mntNS, err := os.Open(mountNSPath)
		if err != nil {
			return nsRestore{}, fmt.Errorf("opening mount namespace %s: %w", mountNSPath, err)
		}
		defer mntNS.Close()
		if err := unix.Setns(int(mntNS.Fd()), unix.CLONE_NEWNS); err != nil {
			// Privileged pods often cannot switch mount namespace (EINVAL).
			if !errors.Is(err, unix.EINVAL) {
				return nsRestore{}, fmt.Errorf("entering mount namespace %s: %w", mountNSPath, err)
			}
			plog.WithError(err).Debug("mount setns unavailable; attaching with cgroup namespace only")
		}
	}

	if cgroupNSPath != "" {
		cgroupNS, err := os.Open(cgroupNSPath)
		if err != nil {
			return nsRestore{}, fmt.Errorf("opening cgroup namespace %s: %w", cgroupNSPath, err)
		}
		defer cgroupNS.Close()
		if err := unix.Setns(int(cgroupNS.Fd()), unix.CLONE_NEWCGROUP); err != nil {
			return nsRestore{}, fmt.Errorf("entering cgroup namespace %s: %w", cgroupNSPath, err)
		}
	}

	return nsRestore{restore: func() {
		_ = unix.Setns(int(selfCgroup.Fd()), unix.CLONE_NEWCGROUP)
		_ = unix.Setns(int(selfMnt.Fd()), unix.CLONE_NEWNS)
	}}, nil
}

// attachCgroupSockopsInHostNS attaches a sockops program using the host cgroup
// namespace. Kubernetes pods otherwise attach at their virtualized cgroup root,
// which does not see kubepods.slice or workload sockets.
func attachCgroupSockopsInHostNS(path string, prog *cilium.Program) (link.Link, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ns, err := enterAttachNamespaces(hostMountNSPath, hostCgroupNSPath)
	if err != nil {
		plog.WithError(err).Debug("host mount/cgroup setns failed; attaching in agent namespaces")
		return attachCgroupSockopsAtPath(path, prog)
	}
	defer ns.Close()

	return attachCgroupSockopsAtPath(path, prog)
}

// attachCgroupSockopsInWorkloadNS attaches sockops from inside the workload's
// cgroup namespace at the host-visible physical cgroup path.
type cgroupAttachResult struct {
	Path string
	Link link.Link
}

func attachCgroupSockopsInWorkloadNS(pid int, prog *cilium.Program) ([]cgroupAttachResult, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid workload pid %d", pid)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	workloadCgroupNS := filepath.Join(procRootDir, strconv.Itoa(pid), "ns", "cgroup")
	ns, err := enterAttachNamespaces(hostMountNSPath, workloadCgroupNS)
	if err != nil {
		return nil, fmt.Errorf("entering workload attach namespaces for pid %d: %w", pid, err)
	}
	defer ns.Close()

	// Inside the workload cgroup namespace only the cgroup root is valid for BPF
	// attach; host-visible leaf paths fail to open from this namespace view.
	cgPath := cgroupRoot()
	cgroupLink, err := attachCgroupSockopsAtPath(cgPath, prog)
	if err != nil {
		return nil, fmt.Errorf("attach at %s: %w", cgPath, err)
	}
	return []cgroupAttachResult{{Path: cgPath, Link: cgroupLink}}, nil
}

func cgroupNSInode(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	dest, err := os.Readlink(filepath.Join(procRootDir, strconv.Itoa(pid), "ns", "cgroup"))
	if err != nil {
		return "", false
	}
	return dest, true
}

// processInIsolatedCgroupNS reports whether pid runs in a cgroup namespace
// different from the node/agent view. With hostPID, /proc/pid/cgroup still
// shows the full kubelet path, so 0::/ cannot be used for detection.
func processInIsolatedCgroupNS(pid int) bool {
	pidNS, ok := cgroupNSInode(pid)
	if !ok {
		return false
	}
	hostNS, ok := cgroupNSInode(1)
	if !ok {
		return false
	}
	return pidNS != hostNS
}

// procCgroupNamespacedRoot reports whether pid's cgroup file shows 0::/ (in-pod view).
func procCgroupNamespacedRoot(pid int) bool {
	if pid <= 0 {
		return false
	}
	data, err := os.ReadFile(filepath.Join(procRootDir, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" && strings.TrimSpace(parts[2]) == "/" {
			return true
		}
	}
	return false
}

func collectKTLSWorkloadCgroupNSPIDs(scope *PlaintextScope) []int {
	if scope == nil {
		return nil
	}
	seenNS := map[string]struct{}{}
	var out []int
	addPID := func(pid int) {
		if pid <= 0 || !processInIsolatedCgroupNS(pid) {
			return
		}
		if scope != nil && len(scope.flowFilterPorts) > 0 && !pidListensOnFilterPorts(pid, scope.flowFilterPorts) {
			return
		}
		ns, ok := cgroupNSInode(pid)
		if !ok {
			return
		}
		if _, dup := seenNS[ns]; dup {
			return
		}
		seenNS[ns] = struct{}{}
		out = append(out, pid)
	}
	for _, ip := range scope.peerIPs {
		for pid := range pidsWithIP(ip) {
			addPID(pid)
		}
	}
	for _, n := range scope.peerNets {
		for pid := range pidsWithIPInNet(n) {
			addPID(pid)
		}
	}
	return out
}
