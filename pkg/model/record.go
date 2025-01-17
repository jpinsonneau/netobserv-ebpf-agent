package model

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

// Values according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
const (
	DirectionIngress = 0
	DirectionEgress  = 1
	MacLen           = 6
	// IPv4Type / IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
	IPv6Type                 = 0x86DD
	NetworkEventsMaxEventsMD = 8
	MaxNetworkEvents         = 4
	MaxObservedInterfaces    = 4
)

type HumanBytes uint64
type MacAddr [MacLen]uint8
type Direction uint8

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

type InterfaceNamer func(ifIndex int) string

var (
	agentIP        net.IP
	interfaceNamer InterfaceNamer = func(ifIndex int) string { return fmt.Sprintf("[namer unset] %d", ifIndex) }
)

func SetGlobals(ip net.IP, ifaceNamer InterfaceNamer) {
	agentIP = ip
	interfaceNamer = ifaceNamer
}

// record structure as parsed from eBPF
type RawRecord ebpf.BpfFlowRecordT

// Record contains accumulated metrics from a flow
type Record struct {
	ID      ebpf.BpfFlowId
	Metrics BpfFlowContent

	// TODO: redundant field from RecordMetrics. Reorganize structs
	TimeFlowStart time.Time
	TimeFlowEnd   time.Time
	DNSLatency    time.Duration
	Interfaces    []IntfDir
	// AgentIP provides information about the source of the flow (the Agent that traced it)
	AgentIP net.IP
	// Calculated RTT which is set when record is created by calling NewRecord
	TimeFlowRtt            time.Duration
	NetworkMonitorEventsMD []config.GenericMap
}

func NewRecord(
	key ebpf.BpfFlowId,
	metrics *BpfFlowContent,
	currentTime time.Time,
	monotonicCurrentTime uint64,
) *Record {
	startDelta := time.Duration(monotonicCurrentTime - metrics.StartMonoTimeTs)
	endDelta := time.Duration(monotonicCurrentTime - metrics.EndMonoTimeTs)

	var record = Record{
		ID:            key,
		Metrics:       *metrics,
		TimeFlowStart: currentTime.Add(-startDelta),
		TimeFlowEnd:   currentTime.Add(-endDelta),
		AgentIP:       agentIP,
		Interfaces:    []IntfDir{NewIntfDir(interfaceNamer(int(metrics.IfIndexFirstSeen)), int(metrics.DirectionFirstSeen))},
	}
	if metrics.AdditionalMetrics != nil {
		for i := uint8(0); i < record.Metrics.AdditionalMetrics.NbObservedIntf; i++ {
			record.Interfaces = append(record.Interfaces, NewIntfDir(
				interfaceNamer(int(metrics.AdditionalMetrics.ObservedIntf[i].IfIndex)),
				int(metrics.AdditionalMetrics.ObservedIntf[i].Direction),
			))
		}
		if metrics.AdditionalMetrics.FlowRtt != 0 {
			record.TimeFlowRtt = time.Duration(metrics.AdditionalMetrics.FlowRtt)
		}
		if metrics.AdditionalMetrics.DnsRecord.Latency != 0 {
			record.DNSLatency = time.Duration(metrics.AdditionalMetrics.DnsRecord.Latency)
		}
	}
	record.NetworkMonitorEventsMD = make([]config.GenericMap, 0)
	return &record
}

type IntfDir struct {
	Interface string
	Direction int
}

func NewIntfDir(intf string, dir int) IntfDir { return IntfDir{Interface: intf, Direction: dir} }

func networkEventsMDExist(events [MaxNetworkEvents][NetworkEventsMaxEventsMD]uint8, md [NetworkEventsMaxEventsMD]uint8) bool {
	for _, e := range events {
		if reflect.DeepEqual(e, md) {
			return true
		}
	}
	return false
}

// IP returns the net.IP equivalent object
func IP(ia IPAddr) net.IP {
	return ia[:]
}

// IntEncodeV4 encodes an IPv4 address as an integer (in network encoding, big endian).
// It assumes that the passed IP is already IPv4. Otherwise, it would just encode the
// last 4 bytes of an IPv6 address
func IntEncodeV4(ia [net.IPv6len]uint8) uint32 {
	return binary.BigEndian.Uint32(ia[net.IPv6len-net.IPv4len : net.IPv6len])
}

// IPAddrFromNetIP returns IPAddr from net.IP
func IPAddrFromNetIP(netIP net.IP) IPAddr {
	var arr [net.IPv6len]uint8
	copy(arr[:], (netIP)[0:net.IPv6len])
	return arr
}

func (ia *IPAddr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + IP(*ia).String() + `"`), nil
}

func (m *MacAddr) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m *MacAddr) MarshalJSON() ([]byte, error) {
	return []byte("\"" + m.String() + "\""), nil
}

// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (*RawRecord, error) {
	var fr RawRecord
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return &fr, err
}

func AllZerosMetaData(s [NetworkEventsMaxEventsMD]uint8) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

func AllZeroIP(ip net.IP) bool {
	if ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6zero) {
		return true
	}
	return false
}
