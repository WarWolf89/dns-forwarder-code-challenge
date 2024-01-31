package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/forwarder"
	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/udpserver"
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

	fwder, err := forwarder.ProvideService(*config)
	if err != nil {
		slog.Error("Error creating the fwder service", err)
	}

	udps, err := udpserver.ProviderUDPServer(config)
	if err != nil {
		slog.Error("error with udp server", err)
	}

	udps.Run(func(ctx context.Context, in []byte, buffer gopacket.SerializeBuffer) error {
		opts := gopacket.SerializeOptions{}

		// create packert with default decoding
		pkt := gopacket.NewPacket(in, layers.LayerTypeDNS, gopacket.Default)
		// create a DNS request from packet
		dnsReq := util.CastToDNSLayer(pkt)
		// slog.Debug("DNS Request incoming from:", "Source Address", sourceAddr)
		dnsResp, err := fwder.FetchDNSRecord(ctx, dnsReq)
		if err != nil {
			slog.Error("Error forwardubg DNS request", "err", err)
			return err
		}

		if err := dnsResp.SerializeTo(buffer, opts); err != nil {
			slog.Error("Error serializing DNS response", err)
			return err
		}
		return nil
	})

	// Wait to get request on that port
	// TODO: is there a better way to do this?

}
