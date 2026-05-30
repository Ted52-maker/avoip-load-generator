// avoip-load-generator — production-style NetFlow v9 UDP load tool for AVoIPCollector (goflow2).
//
// # Build
//
//	go mod tidy
//	go build -o avoip-load-generator .
//
// # Run (examples)
//
//	./avoip-load-generator -target 127.0.0.1:2055 -rate 800 -duration 30m
//	./avoip-load-generator -tenants 20 -rate 5000 -duration 2h -av-ratio 0.7
//	./avoip-load-generator -tenants-file tenants.example.yaml -tenants 15
//
// On Windows, binding to synthetic 192.168.x.1 addresses usually fails unless
// those addresses exist locally; the tool falls back to one UDP socket and
// still varies NetFlow SourceId per tenant so goflow2 can scope templates.
//
// YAML format: see tenants.example.yaml (optional -tenants-file).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"avoip-load-generator/internal/netflowv9"
	"avoip-load-generator/internal/tenant"
	"avoip-load-generator/internal/traffic"
)

// ANSI (works in Windows Terminal / modern conhost). Mutated when -no-color.
var (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

type stats struct {
	flows    atomic.Uint64
	packets  atomic.Uint64
	bytes    atomic.Uint64
	errors   atomic.Uint64
	start    time.Time
	lastTick time.Time
	prevFlow atomic.Uint64
}

func (s *stats) snapshot() (flows, avgPPS, instFPS float64, pkts, errs uint64, uptime time.Duration) {
	now := time.Now()
	f := float64(s.flows.Load())
	dt := now.Sub(s.lastTick).Seconds()
	if dt <= 0 {
		dt = 1
	}
	deltaF := f - float64(s.prevFlow.Load())
	s.prevFlow.Store(uint64(f))
	s.lastTick = now
	elapsed := now.Sub(s.start).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	return f, float64(s.packets.Load()) / elapsed, deltaF / dt, s.packets.Load(), s.errors.Load(), now.Sub(s.start)
}

func parseDurationExt(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "d") {
		n := strings.TrimSuffix(s, "d")
		days, err := parseUint(n)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func parseUint(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid unsigned integer %q", s)
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "%s [flags]\n\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	log.SetFlags(0)

	numTenants := flag.Int("tenants", 15, "Number of simulated exporters / tenants")
	rate := flag.Float64("rate", 800, "Target aggregate flow records per second (total across all tenants)")
	durationStr := flag.String("duration", "30m", "How long to run (Go duration: 30m, 2h, 45s; suffix d for days)")
	target := flag.String("target", "127.0.0.1:2055", "Collector UDP host:port")
	avRatio := flag.Float64("av-ratio", 0.65, "Fraction of flows that look like AV / media traffic (0..1)")
	tenantsFile := flag.String("tenants-file", "", "Optional YAML with id + exporter_ip per tenant (see tenants.example.yaml)")
	ipBase := flag.String("exporter-base", "192.168.100.1", "First synthetic exporter IPv4 when YAML does not define enough tenants")
	riskPct := flag.Float64("risk-pct", 10, "Percent chance (0..100) each UDP packet is a 'risky' burst-style batch")
	bindExporters := flag.Bool("bind-exporters", true, "Try binding a UDP socket per tenant to exporter_ip:0 (disable on constrained hosts)")
	noColor := flag.Bool("no-color", false, "Disable ANSI colors in live stats")

	flag.Usage = usage
	flag.Parse()

	if *noColor {
		ansiReset, ansiBold, ansiDim, ansiYellow, ansiCyan = "", "", "", "", ""
	}

	if *avRatio < 0 || *avRatio > 1 {
		log.Fatalf("-av-ratio must be between 0 and 1")
	}
	if *riskPct < 0 || *riskPct > 100 {
		log.Fatalf("-risk-pct must be between 0 and 100")
	}
	if *numTenants < 1 {
		log.Fatalf("-tenants must be >= 1")
	}
	if *rate <= 0 {
		log.Fatalf("-rate must be > 0")
	}

	dur, err := parseDurationExt(*durationStr)
	if err != nil {
		log.Fatalf("duration: %v", err)
	}

	tenants, err := buildTenants(*numTenants, *tenantsFile, *ipBase)
	if err != nil {
		log.Fatalf("tenants: %v", err)
	}

	raddr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		log.Fatalf("target: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	conns, shared, bindNote := dialTenants(tenants, raddr, *bindExporters)
	if shared != nil {
		defer shared.Close()
	}
	for _, c := range conns {
		if c != nil && c != shared {
			defer c.Close()
		}
	}

	st := &stats{start: time.Now(), lastTick: time.Now()}
	st.prevFlow.Store(0)

	var wg sync.WaitGroup
	stopDisplay := make(chan struct{})
	go displayLoop(ctx, st, len(tenants), stopDisplay)

	maxRec := netflowv9.DataFlowSetMaxRecords()
	perTenantRate := *rate / float64(len(tenants))
	credits := make([]float64, len(tenants))
	seqs := make([]uint32, len(tenants))

	for i := range tenants {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(time.Now().UnixNano())^uint64(i*7919), uint64(i+1)<<40))
			conn := conns[i]
			last := time.Now()

			buf := make([]byte, netflowv9.MaxUDPBytes)

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				now := time.Now()
				dt := now.Sub(last).Seconds()
				last = now
				if dt <= 0 {
					dt = 1e-6
				}
				credits[i] += perTenantRate * dt

				for credits[i] >= 1 {
					n := int(credits[i])
					if n < 1 {
						break
					}
					if n > maxRec {
						n = maxRec
					}
					credits[i] -= float64(n)

					risky := rng.Float64()*100 < *riskPct
					uptime := uint32(time.Since(st.start).Milliseconds())
					unix := uint32(time.Now().Unix())
					seqs[i]++

					pktLen := netflowv9.BuildExportPacket(buf, 2, uptime, unix, seqs[i], tenants[i].SourceID, n, func(_ int, rec []byte) {
						traffic.FillRecord(rec, traffic.Profile{
							AVRatio:   *avRatio,
							TenantIdx: i,
							Risky:     risky,
						}, rng, uptime)
					})

					_, werr := conn.Write(buf[:pktLen])
					if werr != nil {
						st.errors.Add(1)
					} else {
						st.packets.Add(1)
						st.bytes.Add(uint64(pktLen))
						st.flows.Add(uint64(n))
					}
				}

				if credits[i] < 1 {
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}

	fmt.Printf("%savoip-load-generator%s → %s%s%s | tenants=%d rate=%.0f/s duration=%s av-ratio=%.2f risk-pct=%.0f maxRec=%d\n",
		ansiBold, ansiReset, ansiCyan, *target, ansiReset, len(tenants), *rate, dur, *avRatio, *riskPct, maxRec)
	if bindNote != "" {
		fmt.Printf("%s%s%s\n", ansiYellow, bindNote, ansiReset)
	}
	fmt.Printf("%sCtrl+C to stop early (graceful shutdown).%s\n\n", ansiDim, ansiReset)

	wg.Wait()
	close(stopDisplay)
	time.Sleep(50 * time.Millisecond)

	f := st.flows.Load()
	p := st.packets.Load()
	b := st.bytes.Load()
	e := st.errors.Load()
	fmt.Printf("\n%sDone.%s flows=%d packets=%d bytes=%d errors=%d elapsed=%s\n",
		ansiBold+ansiCyan, ansiReset, f, p, b, e, time.Since(st.start).Truncate(time.Second))
	if ctx.Err() == context.Canceled {
		fmt.Printf("%sStopped by user or signal.%s\n", ansiYellow, ansiReset)
	}
}

func buildTenants(want int, file, ipBase string) ([]tenant.Tenant, error) {
	var list []tenant.Tenant
	if file != "" {
		tl, err := tenant.LoadFile(file)
		if err != nil {
			return nil, err
		}
		list = tl
	}
	if len(list) > want {
		list = list[:want]
	}
	base := tenant.ParseIPv4(ipBase)
	if base == nil {
		return nil, fmt.Errorf("bad -exporter-base %q", ipBase)
	}
	if len(list) < want {
		list = tenant.BuildSynthetic(want, base, list)
	}
	return list, nil
}

func dialTenants(tenants []tenant.Tenant, raddr *net.UDPAddr, bind bool) (conns []*net.UDPConn, shared *net.UDPConn, note string) {
	conns = make([]*net.UDPConn, len(tenants))

	shared, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Fatalf("dial collector: %v", err)
	}

	if !bind {
		for i := range tenants {
			conns[i] = shared
		}
		return conns, shared, "bind disabled: using single socket (all traffic shares one source IP)"
	}

	fallback := 0
	for i, t := range tenants {
		la, err := net.ResolveUDPAddr("udp", net.JoinHostPort(t.ExporterIP.String(), "0"))
		if err != nil {
			conns[i] = shared
			fallback++
			continue
		}
		c, err := net.DialUDP("udp", la, raddr)
		if err != nil {
			conns[i] = shared
			fallback++
			continue
		}
		conns[i] = c
	}
	if fallback == len(tenants) {
		note = "Could not bind any per-tenant exporter IP on this host — using one shared socket. " +
			"Add secondary IPv4 addresses or run on Linux with ip addr add, or pass -bind-exporters=false."
	} else if fallback > 0 {
		note = fmt.Sprintf("%d/%d tenants could not bind exporter_ip; those share the primary socket.", fallback, len(tenants))
	}
	for i := range conns {
		if conns[i] == nil {
			conns[i] = shared
		}
	}
	return conns, shared, note
}

func displayLoop(ctx context.Context, st *stats, tenantCount int, stop <-chan struct{}) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			flows, avgPPS, instFPS, pkts, errs, up := st.snapshot()
			line := fmt.Sprintf(
				"%s[%s]%s flows=%s%.0f%s (~%.0f/s inst) packets=%d avg_pkt_rate=%.0f/s errors=%d tenants=%d",
				ansiDim, up.Truncate(time.Second), ansiReset,
				ansiCyan, flows, ansiReset,
				instFPS,
				pkts, avgPPS, errs, tenantCount,
			)
			if errs > 0 {
				line = fmt.Sprintf("%s %serrs=%d%s", line, ansiYellow, errs, ansiReset)
			}
			fmt.Printf("\r%-120s", line)
		}
	}
}
