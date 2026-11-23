//go:build linux && integration

package flows

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	configflows "github.com/netobserv/netobserv-ebpf-agent/pkg/config/flows"
	ebpfflows "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/flows"
	ebpfpackets "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf/packets"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/tracer/internal/netattach"
	"github.com/stretchr/testify/require"
)

// These tests load programs but never attach them to interfaces or processes.
func TestFeatureMapsKernel(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("packets/openssl=%t", enabled), func(t *testing.T) {
			spec, err := ebpfpackets.LoadPacketsBpf()
			require.NoError(t, err)
			prepareFeatureMapTest(spec)
			var flag uint8
			if enabled {
				flag = 1
			}
			netattach.MinimizeMapsIfDisabled(spec, enabled, os.Getpagesize(), "ssl_data_event_map")
			netattach.MinimizeMapsIfDisabled(spec, enabled, 1, "ssl_read_active_map", "ssl_fd_map")
			require.NoError(t, spec.Variables["enable_openssl_tracking"].Set(flag))
			collection, err := cilium.NewCollection(spec)
			require.NoError(t, err, "%+v", err)
			defer collection.Close()
			for _, name := range []string{"ssl_data_event_map", "ssl_read_active_map", "ssl_fd_map"} {
				info, err := collection.Maps[name].Info()
				require.NoError(t, err)
				require.Equal(t, spec.Maps[name].MaxEntries, info.MaxEntries)
			}
		})
	}
}

// TestSpinLockedMapLookupAndDelete checks the kernel behaviour behind
// cilium.LookupLock. aggregated_flows contains a bpf_spin_lock in its value.
func TestSpinLockedMapLookupAndDelete(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := ebpfflows.LoadFlowsBpf()
	require.NoError(t, err)
	prepareFeatureMapTest(spec)

	collection, err := cilium.NewCollection(spec)
	require.NoError(t, err)
	defer collection.Close()

	m := collection.Maps["aggregated_flows"]
	program := collection.Programs["tc_ingress_flow_parse"]
	packet := make([]byte, 64)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14], packet[22], packet[23] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[16:18], 50)
	copy(packet[26:34], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	binary.BigEndian.PutUint16(packet[34:36], 12345)
	binary.BigEndian.PutUint16(packet[36:38], 443)
	binary.BigEndian.PutUint16(packet[38:40], 30)

	_, _, err = program.Test(packet)
	require.NoError(t, err)

	var key ebpfflows.FlowsBpfFlowId
	var initial ebpfflows.FlowsBpfFlowMetrics
	it := m.Iterate()
	require.True(t, it.Next(&key, &initial))
	require.NoError(t, it.Err())

	// Run the real BPF flow parser while userspace repeatedly reads the same
	// value. The writer updates packets and bytes under bpf_spin_lock; a torn
	// snapshot would violate bytes == packets * packet length.
	lookup := func(name string, flags cilium.MapLookupFlags) int {
		const iterations = 20000
		start := make(chan struct{})
		writerDone := make(chan struct{})
		writerErr := make(chan error, 1)
		var writer sync.WaitGroup
		writer.Add(1)
		go func() {
			defer writer.Done()
			defer close(writerDone)
			<-start
			for i := 0; i < iterations; i++ {
				if _, _, err := program.Test(packet); err != nil {
					writerErr <- err
					return
				}
			}
		}()

		close(start)
		mismatches := 0
		for i := 0; i < iterations; i++ {
			var got ebpfflows.FlowsBpfFlowMetrics
			require.NoError(t, m.LookupWithFlags(&key, &got, flags))
			if got.Bytes != uint64(got.Packets)*uint64(len(packet)) {
				mismatches++
				if mismatches <= 3 {
					t.Logf("%s observed torn snapshot: bytes=%d packets=%d", name, got.Bytes, got.Packets)
				}
			}
		}
		<-writerDone
		writer.Wait()
		select {
		case err := <-writerErr:
			require.NoError(t, err)
		default:
		}
		return mismatches
	}

	unflaggedMismatches := lookup("unflagged", 0)
	t.Logf("unflagged mismatches: %d", unflaggedMismatches)

	var discarded ebpfflows.FlowsBpfFlowMetrics
	require.NoError(t, m.LookupAndDeleteWithFlags(&key, &discarded, cilium.LookupLock))
	_, _, err = program.Test(packet)
	require.NoError(t, err)

	flaggedMismatches := lookup("with LookupLock", cilium.LookupLock)
	require.Zero(t, flaggedMismatches)

	var value ebpfflows.FlowsBpfFlowMetrics
	require.NoError(t, m.LookupAndDeleteWithFlags(&key, &value, cilium.LookupLock))
	require.Equal(t, value.Bytes, uint64(value.Packets)*uint64(len(packet)))
}

func TestQUICMapKernel(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())
	for _, mode := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			spec, err := ebpfflows.LoadFlowsBpf()
			require.NoError(t, err)
			prepareFeatureMapTest(spec)
			cfg := &tracer.FetcherConfig{Agent: config.Agent{Common: config.Common{CacheMaxFlows: 32}, Flows: configflows.Features{QUICTrackingMode: mode}}}
			cfg.Normalize()
			configureFlowMaps(spec, cfg, nil, metrics.NoOp())
			require.NoError(t, configureFlowSpecVariables(spec, cfg, nil))
			collection, err := cilium.NewCollection(spec)
			require.NoError(t, err, "%+v", err)
			defer collection.Close()
			for _, port := range []uint16{12345, 12346} {
				packet := make([]byte, 64)
				binary.BigEndian.PutUint16(packet[12:14], 0x0800)
				packet[14], packet[22], packet[23] = 0x45, 64, 17 // IPv4, TTL, UDP
				binary.BigEndian.PutUint16(packet[16:18], 50)
				copy(packet[26:34], []byte{192, 0, 2, 1, 192, 0, 2, 2})
				binary.BigEndian.PutUint16(packet[34:36], port)
				binary.BigEndian.PutUint16(packet[36:38], 443)
				binary.BigEndian.PutUint16(packet[38:40], 30)
				packet[42] = 0x40 // QUIC short header, fixed bit set
				_, _, err = collection.Programs["tc_ingress_flow_parse"].Test(packet)
				require.NoError(t, err)
			}
			count := func(name string) int {
				var key any
				var next []byte
				n := 0
				for next, err = collection.Maps[name].NextKeyBytes(key); err == nil && next != nil; next, err = collection.Maps[name].NextKeyBytes(key) {
					n++
					key = next
				}
				require.NoError(t, err)
				return n
			}
			require.Equal(t, 2, count("aggregated_flows"))
			want := 2
			if mode == 0 {
				want = 0
			}
			require.Equal(t, want, count("quic_flows"))
		})
	}
}

func prepareFeatureMapTest(spec *cilium.CollectionSpec) {
	// Retain TC and OpenSSL programs; unrelated tracing hooks need host modules.
	for name := range spec.Programs {
		if !strings.HasPrefix(name, "tc_ingress_") && !strings.Contains(name, "SSL_") {
			delete(spec.Programs, name)
		}
	}
	for name, m := range spec.Maps {
		m.Pinning = cilium.PinNone
		if strings.HasPrefix(name, "ssl_") || name == "quic_flows" {
			continue
		}
		if m.Type == cilium.RingBuf {
			m.MaxEntries = uint32(os.Getpagesize())
		} else if m.MaxEntries > 32 {
			m.MaxEntries = 32
		}
	}
}
