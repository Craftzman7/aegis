package collector

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aegis-soc/aegis/agent/internal/event"
)

// TCP states from include/net/tcp_states.h.
const (
	TCPEstablished = 0x01
	TCPListen      = 0x0A
)

// Conn is one row of /proc/net/tcp{,6}.
type Conn struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      int
	UID        int
	Inode      uint64
}

// ParseProcNetTCP parses the contents of /proc/net/tcp (v6=false) or tcp6.
func ParseProcNetTCP(r io.Reader, v6 bool) ([]Conn, error) {
	var out []Conn
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		lip, lport, err1 := parseHexAddr(f[1], v6)
		rip, rport, err2 := parseHexAddr(f[2], v6)
		st, err3 := strconv.ParseUint(f[3], 16, 8)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		ino, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Conn{lip, lport, rip, rport, int(st), uid, ino})
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:0050". Addresses are printed as native-endian
// 32-bit words (little-endian on all supported targets).
func parseHexAddr(s string, v6 bool) (net.IP, int, error) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("bad addr %q", s)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return nil, 0, err
	}
	if (!v6 && len(raw) != 4) || (v6 && len(raw) != 16) {
		return nil, 0, fmt.Errorf("bad addr length %q", s)
	}
	ip := make(net.IP, len(raw))
	for i := 0; i+4 <= len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return ip, int(port), nil
}

// ReadProcNet reads tcp and tcp6 from procRoot (normally "/proc").
func ReadProcNet(procRoot string) []Conn {
	var all []Conn
	for _, n := range []struct {
		name string
		v6   bool
	}{{"tcp", false}, {"tcp6", true}} {
		f, err := os.Open(procRoot + "/net/" + n.name)
		if err != nil {
			continue
		}
		cs, _ := ParseProcNetTCP(f, n.v6)
		f.Close()
		all = append(all, cs...)
	}
	return all
}

// NetConn diffs /proc/net/tcp snapshots to report new listeners and
// outbound connections.
type NetConn struct {
	ProcRoot string
	Interval time.Duration
}

func (n *NetConn) Name() string { return "netconn" }

type connKey struct {
	ip   string
	port int
}

// NetState carries the seen-sets between scans.
type NetState struct {
	listen map[connKey]bool
	out    map[string]bool
	primed bool
}

// NewNetState returns an empty state; the first Diff only primes it.
func NewNetState() *NetState {
	return &NetState{listen: map[connKey]bool{}, out: map[string]bool{}}
}

// Diff reports new listeners and new outbound (ESTABLISHED, local port not
// listening, non-loopback) connections since the last call. The first call
// primes the baseline and returns nothing.
func (s *NetState) Diff(conns []Conn) []event.Event {
	first := !s.primed
	s.primed = true
	listenPorts := map[int]bool{}
	for _, c := range conns {
		if c.State == TCPListen {
			listenPorts[c.LocalPort] = true
		}
	}
	ls := event.Logsource{Product: event.ProductLinux, Category: event.CategoryNetworkConnection}
	var evs []event.Event
	for _, c := range conns {
		switch {
		case c.State == TCPListen:
			k := connKey{c.LocalIP.String(), c.LocalPort}
			if s.listen[k] {
				continue
			}
			s.listen[k] = true
			if first {
				continue
			}
			evs = append(evs, event.Event{
				Source: "netconn", Kind: event.KindNetListen, Logsource: ls,
				SourceIp: c.LocalIP.String(), SourcePort: c.LocalPort,
				Extra: map[string]string{"direction": "listen", "uid": strconv.Itoa(c.UID), "inode": strconv.FormatUint(c.Inode, 10)},
			})
		case c.State == TCPEstablished && !listenPorts[c.LocalPort] && !c.RemoteIP.IsLoopback():
			k := c.RemoteIP.String() + ":" + strconv.Itoa(c.RemotePort) + "/" + strconv.FormatUint(c.Inode, 10)
			if s.out[k] {
				continue
			}
			s.out[k] = true
			if first {
				continue
			}
			evs = append(evs, event.Event{
				Source: "netconn", Kind: event.KindNetOutbound, Logsource: ls,
				SourceIp: c.LocalIP.String(), SourcePort: c.LocalPort,
				DestinationIp: c.RemoteIP.String(), DestinationPort: c.RemotePort, Initiated: true,
				Extra: map[string]string{"direction": "outbound", "uid": strconv.Itoa(c.UID), "inode": strconv.FormatUint(c.Inode, 10)},
			})
		}
	}
	return evs
}

func (n *NetConn) Run(ctx context.Context, out chan<- event.Event) error {
	root := n.ProcRoot
	if root == "" {
		root = "/proc"
	}
	iv := n.Interval
	if iv == 0 {
		iv = 5 * time.Second
	}
	st := NewNetState()
	tick(ctx, iv, func() {
		for _, e := range st.Diff(ReadProcNet(root)) {
			emit(ctx, out, e)
		}
	})
	return ctx.Err()
}
