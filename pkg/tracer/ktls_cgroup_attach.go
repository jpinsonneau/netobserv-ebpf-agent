package tracer

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type ktlsCgroupAttacher struct {
	mu              sync.Mutex
	prog            *cilium.Program
	scope           *PlaintextScope
	links           map[string]link.Link
	stopCh          chan struct{}
	warnedNoPeerPID map[string]struct{}
}

func newKTLSCgroupAttacher(prog *cilium.Program, scope *PlaintextScope) *ktlsCgroupAttacher {
	return &ktlsCgroupAttacher{
		prog:            prog,
		scope:           scope,
		links:           map[string]link.Link{},
		stopCh:          make(chan struct{}),
		warnedNoPeerPID: map[string]struct{}{},
	}
}

func (a *ktlsCgroupAttacher) Start() {
	logKTLSCgroupLayout()
	a.refresh()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.stopCh:
				return
			case <-ticker.C:
				a.refresh()
			}
		}
	}()
}

func (a *ktlsCgroupAttacher) Close() {
	close(a.stopCh)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range a.links {
		_ = l.Close()
	}
	a.links = map[string]link.Link{}
}

func (a *ktlsCgroupAttacher) refresh() {
	if a.scope != nil {
		for _, ip := range a.scope.peerIPs {
			if len(pidsWithIP(ip)) == 0 {
				a.warnPeerIPNoPID(ip.String())
			}
		}
	}
	for _, cgPath := range collectKTLSCgroupPaths(a.scope) {
		if err := a.attachIfNeeded(cgPath); err != nil {
			plog.WithError(err).WithField("cgroup", cgPath).Warn("kTLS sockops attach failed")
		}
	}
	for _, pid := range collectKTLSWorkloadCgroupNSPIDs(a.scope) {
		if err := a.attachNamespacedIfNeeded(pid); err != nil {
			plog.WithError(err).WithField("pid", pid).Warn("kTLS sockops attach in workload cgroup namespace failed")
		}
	}
}

func (a *ktlsCgroupAttacher) warnPeerIPNoPID(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.warnedNoPeerPID[ip]; ok {
		return
	}
	a.warnedNoPeerPID[ip] = struct{}{}
	plog.WithField("peer_ip", ip).Warn("kTLS cgroup discovery: no host PIDs for peer_ip (need hostPID and active traffic)")
}

func (a *ktlsCgroupAttacher) attachIfNeeded(cgPath string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.links[cgPath]; ok {
		return nil
	}
	cgroupLink, err := attachCgroupSockopsInHostNS(cgPath, a.prog)
	if err != nil {
		return err
	}
	a.links[cgPath] = cgroupLink
	plog.Infof("kTLS sockops attached at %s", cgPath)
	return nil
}

func (a *ktlsCgroupAttacher) attachNamespacedIfNeeded(pid int) error {
	ns, ok := cgroupNSInode(pid)
	if !ok {
		return nil
	}
	results, err := attachCgroupSockopsInWorkloadNS(pid, a.prog)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, result := range results {
		linkKey := "cgroup-ns:" + ns + ":" + result.Path
		if _, ok := a.links[linkKey]; ok {
			_ = result.Link.Close()
			continue
		}
		a.links[linkKey] = result.Link
		plog.Infof("kTLS sockops attached in workload cgroup namespace (pid=%d path=%s)", pid, result.Path)
	}
	return nil
}

func cgroupPathsForPID(pid int) []string {
	path, ok := cgroupHostFilesystemPathForPID(pid)
	if !ok {
		return nil
	}
	return []string{path}
}

func procCgroupRelPath(pid int) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	data, err := os.ReadFile(filepath.Join(procRootDir, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", false
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
		// cgroup v2: "0::/kubepods.slice/..." or "0::/" in cgroup namespace
		if parts[0] == "0" && parts[1] == "" {
			rel := strings.TrimPrefix(parts[2], "/")
			return rel, true
		}
	}
	return "", false
}
