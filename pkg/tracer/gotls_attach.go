package tracer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sirupsen/logrus"
)

var glog = logrus.WithField("component", "tracer.gotls")

type goTLSInode struct {
	dev uint64
	ino uint64
}

// gotlsAttacher discovers Go binaries from /proc and attaches TLS uprobes.
type gotlsAttacher struct {
	cfg           *FlowFetcherConfig
	writeProg     *ebpf.Program
	readProg      *ebpf.Program
	readRetProg   *ebpf.Program
	links         []link.Link
	attached      map[string]bool
	attachedInode map[goTLSInode]bool
	mu            sync.Mutex
	stopCh        chan struct{}
}

func startGoTLSAttacher(cfg *FlowFetcherConfig, writeProg, readProg, readRetProg *ebpf.Program) (*gotlsAttacher, error) {
	if writeProg == nil && readProg == nil && readRetProg == nil {
		return nil, fmt.Errorf("no GoTLS programs loaded")
	}
	attacher := &gotlsAttacher{
		cfg:           cfg,
		writeProg:     writeProg,
		readProg:      readProg,
		readRetProg:   readRetProg,
		attached:      map[string]bool{},
		attachedInode: map[goTLSInode]bool{},
		stopCh:        make(chan struct{}),
	}
	attacher.Start()
	return attacher, nil
}

func (a *gotlsAttacher) Start() {
	glog.Info("starting GoTLS uprobe scanner")
	a.scanOnce()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-a.stopCh:
				return
			case <-ticker.C:
				a.scanOnce()
			}
		}
	}()
}

func (a *gotlsAttacher) Close() {
	close(a.stopCh)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range a.links {
		_ = l.Close()
	}
	a.links = nil
	a.attached = map[string]bool{}
	a.attachedInode = map[goTLSInode]bool{}
}

func (a *gotlsAttacher) scanOnce() {
	paths := a.discoverPaths()
	if len(paths) == 0 {
		if a.cfg.PlaintextScope != nil && a.cfg.PlaintextScope.IsPIDScopeActive() {
			glog.Warn("GoTLS discovery found no scoped Go binaries (check hostPID, peer_ip, and active TLS traffic to the target pod)")
		} else {
			glog.Debug("no Go binaries discovered for TLS capture")
		}
		return
	}
	if a.cfg.PlaintextScope != nil && !a.cfg.PlaintextScope.IsPIDScopeActive() {
		glog.Warnf("GoTLS attaching to %d Go binaries without peer scope (recommended: peer_ip/peer_cidr in FLOW_FILTER_RULES)", len(paths))
	}
	before := len(a.attached)
	for _, p := range paths {
		a.attachBinary(p)
	}
	if len(a.attached) > before {
		glog.Infof("GoTLS uprobe attachment count is now %d", len(a.attached))
	}
}

func (a *gotlsAttacher) discoverPaths() []string {
	if a.cfg.GoTLSElfPath != "" {
		if isGoExecutable(a.cfg.GoTLSElfPath) {
			return []string{a.cfg.GoTLSElfPath}
		}
		glog.WithField("path", a.cfg.GoTLSElfPath).Warn("GOTLS_ELF_PATH is not a Go executable")
		return nil
	}

	seenInode := map[goTLSInode]bool{}
	var paths []string
	selfPID := os.Getpid()

	_ = filepath.WalkDir(procRootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		pidStr := filepath.Base(path)
		if pidStr == filepath.Base(procRootDir) || !isNumeric(pidStr) {
			return nil
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid == selfPID {
			return nil
		}
		if a.cfg.PlaintextScope != nil && !a.cfg.PlaintextScope.PIDAllowed(pid) {
			return nil
		}
		if isPlaintextCaptureExcludedPID(pidStr, a.cfg.PlaintextScope) {
			return nil
		}

		exePath := filepath.Join(procRootDir, pidStr, "exe")
		if !isGoExecutable(exePath) {
			return nil
		}
		resolved, comm := resolveProcExe(pidStr, exePath)
		if isPlaintextCaptureExcludedPID(pidStr, a.cfg.PlaintextScope) {
			glog.WithFields(logrus.Fields{
				"pid":      pidStr,
				"comm":     comm,
				"exe":      resolved,
				"proc_exe": exePath,
			}).Debug("skipping excluded Go binary for GoTLS capture")
			return nil
		}
		dev, ino, err := statInode(exePath)
		if err != nil {
			return nil
		}
		key := goTLSInode{dev: dev, ino: ino}
		if seenInode[key] {
			return nil
		}
		seenInode[key] = true
		paths = append(paths, exePath)
		return nil
	})
	return paths
}

func (a *gotlsAttacher) attachBinary(binPath string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.attached[binPath] {
		return
	}
	dev, ino, inodeErr := statInode(binPath)
	if inodeErr == nil {
		key := goTLSInode{dev: dev, ino: ino}
		if a.attachedInode[key] {
			return
		}
	}

	offsets, err := a.resolveOffsets(binPath)
	if err != nil {
		glog.WithError(err).Debugf("skipping GoTLS attach for %s", binPath)
		return
	}
	if !offsets.RegisterABI {
		glog.WithField("go", offsets.GoVersion).Warnf("GoTLS auto-discovery requires Go 1.17+ register ABI: %s", binPath)
		return
	}

	exe, err := link.OpenExecutable(binPath)
	if err != nil {
		glog.WithError(err).Warnf("cannot open Go binary %s", binPath)
		return
	}

	attached := false
	if a.writeProg != nil {
		writeOff := offsets.WriteOffset
		if a.cfg.GoTLSWriteOffset > 0 {
			writeOff = a.cfg.GoTLSWriteOffset
		}
		l, err := attachGoTLSUprobe(exe, a.writeProg, writeOff)
		if err != nil {
			glog.WithError(err).Warnf("GoTLS write uprobe failed on %s at %d", binPath, writeOff)
		} else {
			a.links = append(a.links, l)
			glog.Infof("attached GoTLS write uprobe to %s at offset 0x%x (go %s)", binPath, writeOff, offsets.GoVersion)
			attached = true
		}
	}

	if a.readProg != nil {
		readEntry := offsets.ReadEntry
		if a.cfg.GoTLSReadRetSites {
			readOffsets := offsets.ReadReturns
			if a.cfg.GoTLSReadOffset > 0 {
				readOffsets = []uint64{a.cfg.GoTLSReadOffset}
			}
			retAttached := 0
			for _, off := range readOffsets {
				l, err := attachGoTLSUprobe(exe, a.readProg, off)
				if err != nil {
					glog.WithError(err).Warnf("GoTLS read RET uprobe failed on %s at 0x%x", binPath, off)
					continue
				}
				a.links = append(a.links, l)
				retAttached++
				attached = true
			}
			if retAttached > 0 {
				glog.Infof("attached GoTLS read RET uprobes to %s (%d sites, go %s)", binPath, retAttached, offsets.GoVersion)
			}
		} else if a.readRetProg != nil {
			entryLink, err := attachGoTLSUprobe(exe, a.readProg, readEntry)
			if err != nil {
				glog.WithError(err).Warnf("GoTLS read entry uprobe failed on %s at 0x%x", binPath, readEntry)
			} else {
				a.links = append(a.links, entryLink)
				retLink, err := attachGoTLSUretprobe(exe, a.readRetProg, readEntry)
				if err != nil {
					glog.WithError(err).Warnf("GoTLS read uretprobe failed on %s at 0x%x", binPath, readEntry)
				} else {
					a.links = append(a.links, retLink)
					glog.Infof("attached GoTLS read entry+uretprobe to %s at 0x%x (go %s)", binPath, readEntry, offsets.GoVersion)
					attached = true
				}
			}
		}
	}

	if attached {
		a.attached[binPath] = true
		if inodeErr == nil {
			a.attachedInode[goTLSInode{dev: dev, ino: ino}] = true
			if a.cfg.PlaintextScope != nil {
				if layout, layoutErr := ResolveGoTLSFDLayout(binPath, offsets.GoVersion); layoutErr == nil {
					a.cfg.PlaintextScope.RegisterGoTLSFDLayout(dev, ino, layout)
				}
			}
		}
	}
}

func (a *gotlsAttacher) resolveOffsets(binPath string) (*GoTLSOffsets, error) {
	if a.cfg.GoTLSWriteOffset > 0 && a.cfg.GoTLSReadOffset > 0 {
		return &GoTLSOffsets{
			WriteOffset: a.cfg.GoTLSWriteOffset,
			ReadEntry:   a.cfg.GoTLSReadOffset,
			ReadReturns: []uint64{a.cfg.GoTLSReadOffset},
			RegisterABI: true,
		}, nil
	}
	return ResolveGoTLSOffsets(binPath)
}

// attachGoTLSUprobes is kept for callers that expect a one-shot attach API.
func attachGoTLSUprobes(cfg *FlowFetcherConfig, writeProg, readProg, readRetProg *ebpf.Program) (*gotlsAttacher, error) {
	return startGoTLSAttacher(cfg, writeProg, readProg, readRetProg)
}

// attachGoTLSUprobe attaches at an absolute file offset (stripped Go binaries have no ELF symbols).
func attachGoTLSUprobe(exe *link.Executable, prog *ebpf.Program, fileOffset uint64) (link.Link, error) {
	return exe.Uprobe("", prog, &link.UprobeOptions{Address: fileOffset})
}

// attachGoTLSUretprobe fires on return from the function at fileOffset (single hook vs per-RET uprobes).
func attachGoTLSUretprobe(exe *link.Executable, prog *ebpf.Program, fileOffset uint64) (link.Link, error) {
	return exe.Uretprobe("", prog, &link.UprobeOptions{Address: fileOffset})
}
