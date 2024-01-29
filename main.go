package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

func main() {

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

	// create custom resolver pointing to google's address
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, "8.8.8.8:53")
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
		dnsRequest := deSerialize(pkt)
		slog.Info("Request parameters are:", "Source Address", sourceAddr, "DNS Request body", dnsRequest)

		ip, _ := r.LookupHost(context.Background(), "www.google.com")
		slog.Info("IP for lookup request is", "IP", ip)
		forwardDNS(&ctx, r, dnsRequest)
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
	dnsResponse := layers.DNS{}
	for _, q := range dnsReq.Questions {
		var dnsRecord layers.DNSResourceRecord
		// append the DNS question to the answer
		dnsResponse.Questions = append(dnsResponse.Questions, q)
		// we're only looking up ip4 addresses here
		ips, err := r.LookupIP(*ctx, "ip4", string(q.Name))
		if err != nil {
			slog.Error("Error when looking up host ip for query", "Query Name:", q.Name)
		}

		// loop through ip addresses and add as record to answer
		for _, ip := range ips {
			dnsRecord.IP = ip
			dnsResponse.Answers = append(dnsResponse.Answers, dnsRecord)
		}
	}
	return dnsResponse, nil

}
