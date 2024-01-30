package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/forwarder"
	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

func main() {
	config, err := util.LoadConfig("test_config")
	// exit immediately on non-recoverable(e.g. path issue) config load errors
	if err != nil {
		slog.Warn("Unrecoverable error when loading config file", "error", err)
		os.Exit(1)
	}

	// create custom resolver pointing to the address specified in the config
	// TODO extract to internal type and remove from main.go
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, fmt.Sprintf("%s:%d", net.ParseIP(config.ResolverAddr), config.ResolverPort))
		},
	}

	// move to cache layer in pkg
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,     // number of keys to track frequency of (10M).
		MaxCost:     1 << 30, // maximum cost of cache (1GB).
		BufferItems: 64,      // number of keys per Get buffer.
	})
	if err != nil {
		slog.Error("Error setting up cache", err)
		panic(err)
	}

	// TODO extract to UDP package
	//Listen on UDP Port
	addr := net.UDPAddr{
		Port: config.ServerPort,
		IP:   net.ParseIP(config.ServerAddr),
	}
	u, err := net.ListenUDP("udp", &addr)
	if err != nil {
		slog.Error("Error when starting UDP server", err)
		os.Exit(1)
	}

	// Wait to get request on that port
	// TODO: is there a better way to do this?
	for {
		ctx := context.Background()
		tmp := make([]byte, 1024)
		// no need to handle byte count for buffer, see https://pkg.go.dev/net#PacketConn
		_, sourceAddr, err := u.ReadFrom(tmp)
		if err != nil {
			slog.Error("Error reading from buffer for DNS query", "err", err)
		}

		// create packert with default decoding
		pkt := gopacket.NewPacket(tmp, layers.LayerTypeDNS, gopacket.Default)
		// create a DNS request from packet
		dnsReq := util.CastToDNSLayer(pkt)
		slog.Debug("DNS Request incoming from:", "Source Address", sourceAddr)
		dnsResp, err := forwarder.FetchDNSRecord(&ctx, *cache, dnsReq, r)
		if err != nil {
			slog.Error("Error forwardubg DNS request", "err", err)
			continue
		}

		u.WriteTo(dnsResp.([]byte), sourceAddr)
	}
}
