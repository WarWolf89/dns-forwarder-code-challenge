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

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

type Resolver struct {
	res  *net.Resolver
	Addr string
	Port int
}

func (r Resolver) forwardDNS(ctx *context.Context, dnsReq *layers.DNS) (layers.DNS, error) {
	dnsResp := layers.DNS{
		ID: dnsReq.ID,
		QR: true,
		AA: true,
		RD: true,
		RA: true,
	}

	for _, q := range dnsReq.Questions {
		// we're only looking up ip4 addresses here
		ips, err := r.res.LookupIP(*ctx, "ip4", string(q.Name))
		if err != nil {
			dnsResp.ResponseCode = layers.DNSResponseCodeFormErr
			slog.Error("Error when looking up host ip for query", "Query Name:", q.Name)
			return dnsResp, err
		}
		// loop through ip addresses and add as record to answer
		for _, ip := range ips {
			rr := layers.DNSResourceRecord{
				Name:  []byte(q.Name),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   60,
			}
			rr.IP = ip
			dnsResp.Answers = append(dnsResp.Answers, rr)
			dnsResp.ANCount++
			dnsResp.OpCode = layers.DNSOpCodeQuery
			dnsResp.ResponseCode = layers.DNSResponseCodeNoErr
		}
	}
	return dnsResp, nil
}

func fetchDNSRecord(ctx *context.Context, cache ristretto.Cache, dnsReq *layers.DNS, r *Resolver) (interface{}, error) {
	// Serialize the DNS response packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	for _, q := range dnsReq.Questions {
		record, found := cache.Get(q.Name)
		if !found {
			record, err := r.forwardDNS(ctx, dnsReq)
			if err != nil {
				return nil, err
			}
			if err := record.SerializeTo(buf, opts); err != nil {
				slog.Error("Error serializing DNS response", err)
				continue
			}
			cache.Set(q.Name, buf.Bytes(), 0)
			return buf.Bytes(), nil
		}
		return record, nil
	}
	return buf.Bytes(), nil
}

func main() {
	config, err := util.LoadConfig("test_config")
	// exit immediately on non-recoverable(e.g. path issue) config load errors
	if err != nil {
		slog.Warn("Unrecoverable error when loading config file", "error", err)
		os.Exit(1)
	}

	// create custom resolver pointing to the address specified in the config
	r := Resolver{
		res: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, fmt.Sprintf("%s:%d", net.ParseIP(config.ResolverAddr), config.ResolverPort))
			},
		},
		Addr: config.ResolverAddr,
		Port: config.ResolverPort,
	}

	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,     // number of keys to track frequency of (10M).
		MaxCost:     1 << 30, // maximum cost of cache (1GB).
		BufferItems: 64,      // number of keys per Get buffer.
	})
	if err != nil {
		slog.Error("Error setting up cache", err)
		panic(err)
	}

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
		dnsReq := deSerialize(pkt)
		slog.Debug("DNS Request incoming from:", "Source Address", sourceAddr)
		dnsResp, err := fetchDNSRecord(&ctx, *cache, dnsReq, &r)
		if err != nil {
			slog.Error("Error forwardubg DNS request", "err", err)
			continue
		}

		u.WriteTo(dnsResp.([]byte), sourceAddr)
	}
}

func deSerialize(pkt gopacket.Packet) *layers.DNS {
	dnsPacket := pkt.Layer(layers.LayerTypeDNS)
	if dnsPacket == nil {
		slog.Error("No DNS type layer on pkt")
	}

	req, ok := dnsPacket.(*layers.DNS)
	if !ok {
		slog.Error("Type assertion error on packet interface is: ", "interface", req)
	}
	return req
}
