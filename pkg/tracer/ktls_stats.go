package tracer

import (
	"time"

	cilium "github.com/cilium/ebpf"
)

const (
	ktlsStatSockopsEstablished = 0
	ktlsStatSockhashUpdated    = 1
	ktlsStatSkMsgEnter         = 2
	ktlsStatSkMsgCaptured      = 3
	ktlsStatSockopsEnter       = 4
	ktlsStatSockopsOpConnect   = 5
	ktlsStatSockopsOpActive    = 6
	ktlsStatSockopsOpPassive   = 7
	ktlsStatSockopsOpListen    = 8
	ktlsStatSockopsOpOther     = 9
	ktlsStatSockopsOpRTT       = 10
	ktlsStatSockopsOpState     = 11
	ktlsStatSockhashFromRTT    = 12
	ktlsStatSockhashUpdateErr  = 13
	ktlsStatSockhashTry        = 14
	ktlsStatSockhashNotFullsock = 15
)

type ktlsStats struct {
	SockopsEstablished uint64
	SockhashUpdated    uint64
	SkMsgEnter         uint64
	SkMsgCaptured      uint64
	SockopsEnter       uint64
	SockopsOpConnect   uint64
	SockopsOpActive    uint64
	SockopsOpPassive   uint64
	SockopsOpListen    uint64
	SockopsOpOther     uint64
	SockopsOpRTT       uint64
	SockopsOpState     uint64
	SockhashFromRTT    uint64
	SockhashUpdateErr  uint64
	SockhashTry        uint64
	SockhashNotFullsock uint64
}

func readKTLSStats(m *cilium.Map) (ktlsStats, error) {
	var out ktlsStats
	if m == nil {
		return out, nil
	}
	keys := []uint32{
		ktlsStatSockopsEstablished,
		ktlsStatSockhashUpdated,
		ktlsStatSkMsgEnter,
		ktlsStatSkMsgCaptured,
		ktlsStatSockopsEnter,
		ktlsStatSockopsOpConnect,
		ktlsStatSockopsOpActive,
		ktlsStatSockopsOpPassive,
		ktlsStatSockopsOpListen,
		ktlsStatSockopsOpOther,
		ktlsStatSockopsOpRTT,
		ktlsStatSockopsOpState,
		ktlsStatSockhashFromRTT,
		ktlsStatSockhashUpdateErr,
		ktlsStatSockhashTry,
		ktlsStatSockhashNotFullsock,
	}
	vals := make([]uint64, 0, 64)
	for _, key := range keys {
		vals = vals[:0]
		if err := m.Lookup(key, &vals); err != nil {
			return out, err
		}
		var total uint64
		for _, v := range vals {
			total += v
		}
		switch key {
		case ktlsStatSockopsEstablished:
			out.SockopsEstablished = total
		case ktlsStatSockhashUpdated:
			out.SockhashUpdated = total
		case ktlsStatSkMsgEnter:
			out.SkMsgEnter = total
		case ktlsStatSkMsgCaptured:
			out.SkMsgCaptured = total
		case ktlsStatSockopsEnter:
			out.SockopsEnter = total
		case ktlsStatSockopsOpConnect:
			out.SockopsOpConnect = total
		case ktlsStatSockopsOpActive:
			out.SockopsOpActive = total
		case ktlsStatSockopsOpPassive:
			out.SockopsOpPassive = total
		case ktlsStatSockopsOpListen:
			out.SockopsOpListen = total
		case ktlsStatSockopsOpOther:
			out.SockopsOpOther = total
		case ktlsStatSockopsOpRTT:
			out.SockopsOpRTT = total
		case ktlsStatSockopsOpState:
			out.SockopsOpState = total
		case ktlsStatSockhashFromRTT:
			out.SockhashFromRTT = total
		case ktlsStatSockhashUpdateErr:
			out.SockhashUpdateErr = total
		case ktlsStatSockhashTry:
			out.SockhashTry = total
		case ktlsStatSockhashNotFullsock:
			out.SockhashNotFullsock = total
		}
	}
	return out, nil
}

func ktlsStatsFields(stats ktlsStats) map[string]interface{} {
	return map[string]interface{}{
		"sockops_enter":       stats.SockopsEnter,
		"sockops_established": stats.SockopsEstablished,
		"sockops_passive":     stats.SockopsOpPassive,
		"sockops_active":      stats.SockopsOpActive,
		"sockops_rtt":         stats.SockopsOpRTT,
		"sockops_other":       stats.SockopsOpOther,
		"sockhash_try":         stats.SockhashTry,
		"sockhash_not_fullsock": stats.SockhashNotFullsock,
		"sockhash_updated":     stats.SockhashUpdated,
		"sockhash_update_err": stats.SockhashUpdateErr,
		"sockhash_from_rtt":   stats.SockhashFromRTT,
		"sk_msg_enter":        stats.SkMsgEnter,
		"sk_msg_captured":     stats.SkMsgCaptured,
	}
}

func startKTLSStatsLogger(m *cilium.Map, stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				stats, err := readKTLSStats(m)
				if err != nil {
					plog.WithError(err).Debug("reading kTLS stats map")
					continue
				}
				fields := ktlsStatsFields(stats)
				if stats.SockopsEstablished == 0 && stats.SkMsgEnter == 0 {
					plog.WithFields(fields).Warn("kTLS BPF stats: idle (restart traffic after agent is up; existing TCP connections are not re-instrumented)")
					continue
				}
				plog.WithFields(fields).Info("kTLS BPF stats")
			}
		}
	}()
}
