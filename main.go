package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

func main() {

	// Serialize the DNS response packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	config, err := util.LoadConfig("test_config")
	// exit immediately on non-recoverable(e.g. path issue) config load errors
	if err != nil {
		slog.Warn("Unrecoverable error when loading config file", "error", err)
		os.Exit(1)
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

	// create custom resolver pointing to the address specified in the config
	r := &net.Resolver{
		PreferGo: true,
		// definitely clean this up
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, fmt.Sprintf("%s:%d", net.ParseIP(config.ResolverAddr), config.ResolverPort))
		},
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
		dnsResp, err := forwardDNS(&ctx, r, dnsReq)
		if err != nil {
			slog.Error("Error forwardubg DNS request", "err", err)
			continue
		}

		if err := dnsResp.SerializeTo(buf, opts); err != nil {
			slog.Error("Error serializing DNS response", err)
			continue
		}
		u.WriteTo(buf.Bytes(), sourceAddr)
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

func forwardDNS(ctx *context.Context, r *net.Resolver, dnsReq *layers.DNS) (layers.DNS, error) {
	dnsResp := layers.DNS{
		ID: dnsReq.ID,
		QR: true,
		AA: true,
		RD: true,
		RA: true,
	}

	for _, q := range dnsReq.Questions {
		// we're only looking up ip4 addresses here
		ips, err := r.LookupIP(*ctx, "ip4", string(q.Name))
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
