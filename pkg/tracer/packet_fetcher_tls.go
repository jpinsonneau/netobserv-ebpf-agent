package tracer

import (
	"errors"
	"fmt"
	"os"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	agentebpf "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

const (
	constEnableGoTLSTracking = "enable_gotls_tracking"
	constEnableKTLSTracking  = "enable_ktls_tracking"
	sockHashMap              = "sock_hash"
)

func tlsPlaintextEnabled(cfg *FlowFetcherConfig) bool {
	return cfg.EnableOpenSSLTracking || cfg.EnableGoTLSTracking || cfg.EnableKTLSTracking
}

func opensslTrackingEnabled(cfg *FlowFetcherConfig) bool {
	return cfg.EnableOpenSSLTracking
}

func setTLSCaptureVariables(spec *cilium.CollectionSpec, cfg *FlowFetcherConfig) error {
	enableOpenSSL := 0
	if opensslTrackingEnabled(cfg) {
		enableOpenSSL = 1
	}
	enableGoTLS := 0
	if cfg.EnableGoTLSTracking {
		enableGoTLS = 1
	}
	enableKTLS := 0
	if cfg.EnableKTLSTracking {
		enableKTLS = 1
	}
	vars := []variablesMapping{
		{constEnableOpenSSLTracking, uint8(enableOpenSSL)},
		{constEnableGoTLSTracking, uint8(enableGoTLS)},
		{constEnableKTLSTracking, uint8(enableKTLS)},
	}
	for _, v := range vars {
		if err := setVariable(spec, v.key, v.value); err != nil {
			return err
		}
	}
	return nil
}

type tlsBpfPrograms struct {
	ProbeEntrySSLWrite       *cilium.Program `ebpf:"probe_entry_SSL_write"`
	ProbeEntrySSLSetFd       *cilium.Program `ebpf:"probe_entry_SSL_set_fd"`
	ProbeEntrySSLRead        *cilium.Program `ebpf:"probe_entry_SSL_read"`
	ProbeRetSSLRead          *cilium.Program `ebpf:"probe_ret_SSL_read"`
	ProbeEntryGotlsWrite     *cilium.Program `ebpf:"probe_entry_gotls_write"`
	ProbeEntryGotlsRead      *cilium.Program `ebpf:"probe_entry_gotls_read"`
	ProbeRetGotlsRead        *cilium.Program `ebpf:"probe_ret_gotls_read"`
	ProbeEntryGotlsReadRet   *cilium.Program `ebpf:"probe_entry_gotls_read_ret"`
	BpfSockops               *cilium.Program `ebpf:"bpf_sockops"`
	BpfKtlsRedir             *cilium.Program `ebpf:"bpf_ktls_redir"`
}

type packetFetcherTLS struct {
	sslReader         *ringbuf.Reader
	opensslAttacher   *opensslAttacher
	gotlsAttacher     *gotlsAttacher
	ktlsCgroupAttach  *ktlsCgroupAttacher
	ktlsStatsStop     chan struct{}
}

func setupPacketFetcherTLS(spec *cilium.CollectionSpec, cfg *FlowFetcherConfig, maps *agentebpf.BpfMaps, progs *tlsBpfPrograms) (*packetFetcherTLS, error) {
	if !tlsPlaintextEnabled(cfg) {
		return nil, nil
	}

	if err := setTLSCaptureVariables(spec, cfg); err != nil {
		return nil, err
	}

	reader, err := ringbuf.NewReader(maps.SslDataEventMap)
	if err != nil {
		return nil, fmt.Errorf("accessing SSL data event ringbuffer: %w", err)
	}

	result := &packetFetcherTLS{sslReader: reader}

	if opensslTrackingEnabled(cfg) {
		if cfg.PlaintextScope == nil || !cfg.PlaintextScope.IsPIDScopeActive() {
			plog.Warn("OpenSSL libssl discovery is not peer-scoped; attaches per-container libssl on this node — set peer_ip/peer_cidr in FLOW_FILTER_RULES to narrow")
		}
		attacher, err := attachOpenSSLUprobes(cfg, progs.ProbeEntrySSLWrite, progs.ProbeEntrySSLRead, progs.ProbeRetSSLRead, progs.ProbeEntrySSLSetFd)
		if err != nil {
			return nil, err
		}
		result.opensslAttacher = attacher
		plog.Infof("OpenSSL TLS plaintext capture enabled (OPENSSL_PATH=%s)", cfg.OpenSSLPath)
	}

	if cfg.EnableGoTLSTracking {
		if cfg.PlaintextScope == nil || !cfg.PlaintextScope.IsPIDScopeActive() {
			plog.Warn("GoTLS auto-discovery is not peer-scoped; hooks all non-excluded Go binaries on this node — set peer_ip/peer_cidr in FLOW_FILTER_RULES or TLS_PLAINTEXT_PID_ALLOWLIST to narrow")
		}
		var readProg, readRetProg *cilium.Program
		if cfg.GoTLSCaptureRead {
			if cfg.GoTLSReadRetSites {
				readProg = progs.ProbeEntryGotlsReadRet
				plog.Info("GoTLS read capture enabled (legacy per-RET uprobes)")
			} else {
				readProg = progs.ProbeEntryGotlsRead
				readRetProg = progs.ProbeRetGotlsRead
				plog.Info("GoTLS read capture enabled (entry uprobe + uretprobe at crypto/tls.(*Conn).Read)")
			}
		} else {
			plog.Info("GoTLS read capture disabled (GOTLS_CAPTURE_READ=false); capturing write path only")
		}
		attacher, err := startGoTLSAttacher(cfg, progs.ProbeEntryGotlsWrite, readProg, readRetProg)
		if err != nil {
			plog.WithError(err).Warn("GoTLS tracking disabled")
		} else {
			result.gotlsAttacher = attacher
		}
	}

	if cfg.EnableKTLSTracking {
		if cfg.PlaintextScope == nil || !cfg.PlaintextScope.IsPIDScopeActive() {
			plog.Warn("kTLS cgroup hooks are node-wide; set peer_ip/peer_cidr in FLOW_FILTER_RULES to target a workload pod")
		}
		if err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  maps.SockHash.FD(),
			Program: progs.BpfKtlsRedir,
			Attach:  cilium.AttachSkMsgVerdict,
		}); err != nil {
			return nil, fmt.Errorf("attaching sk_msg program: %w", err)
		}
		// Attach sk_msg to sock_hash before sockops so sockets added via
		// bpf_sock_hash_update inherit the verdict program.
		attacher := newKTLSCgroupAttacher(progs.BpfSockops, cfg.PlaintextScope)
		attacher.Start()
		result.ktlsCgroupAttach = attacher

		result.ktlsStatsStop = make(chan struct{})
		startKTLSStatsLogger(maps.KtlsStats, result.ktlsStatsStop)
		plog.Infof("kTLS tracking enabled (cgroup root=%s)", cgroupRoot())
	}

	return result, nil
}

func closePacketFetcherTLS(pf *PacketFetcher) {
	if pf.sslDataEventsReader != nil {
		_ = pf.sslDataEventsReader.Close()
		pf.sslDataEventsReader = nil
	}
	if pf.opensslAttacher != nil {
		pf.opensslAttacher.Close()
		pf.opensslAttacher = nil
	}
	if pf.gotlsAttacher != nil {
		pf.gotlsAttacher.Close()
		pf.gotlsAttacher = nil
	}
	if pf.tlsCgroupAttach != nil {
		pf.tlsCgroupAttach.Close()
		pf.tlsCgroupAttach = nil
	}
	if pf.ktlsStatsStop != nil {
		close(pf.ktlsStatsStop)
		pf.ktlsStatsStop = nil
	}
}

func closePacketFetcherPrograms(objects *agentebpf.BpfObjects) error {
	if objects == nil {
		return nil
	}
	var errs []error
	closers := []*cilium.Program{
		objects.TcEgressPcaParse,
		objects.TcIngressPcaParse,
		objects.TcxEgressPcaParse,
		objects.TcxIngressPcaParse,
	}
	for _, prog := range closers {
		if prog != nil {
			if err := prog.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if objects.PacketRecord != nil {
		if err := objects.PacketRecord.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *packetFetcherTLS) Close() {
	if t == nil {
		return
	}
	if t.sslReader != nil {
		_ = t.sslReader.Close()
	}
	if t.opensslAttacher != nil {
		t.opensslAttacher.Close()
	}
	if t.gotlsAttacher != nil {
		t.gotlsAttacher.Close()
	}
	if t.ktlsCgroupAttach != nil {
		t.ktlsCgroupAttach.Close()
	}
	if t.ktlsStatsStop != nil {
		close(t.ktlsStatsStop)
	}
}

func tlsMapSizing(spec *cilium.CollectionSpec, cfg *FlowFetcherConfig) {
	minEntries := uint32(os.Getpagesize())
	if !tlsPlaintextEnabled(cfg) {
		spec.Maps[sslDataEventMap].MaxEntries = minEntries
	}
	if !cfg.EnableKTLSTracking {
		spec.Maps[sockHashMap].MaxEntries = 1
	}
}
