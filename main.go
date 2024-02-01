package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"

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

	fwder, err := forwarder.ProvideService(*config)
	if err != nil {
		slog.Error("Error creating the fwder service", err)
	}

	srv := &dns.Server{Addr: fmt.Sprintf("%s:%d", config.ServerAddr, config.ServerPort), Net: "udp"}
	srv.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		ctx := context.Background()
		dnsResp, err := fwder.FetchDNSRecord(ctx, r)
		if err != nil {
			slog.Error("Error when forwarding DNS request")
		}
		if err := w.WriteMsg(dnsResp); err != nil {
			slog.Error("Error writing message to client", err)
		}
	})

	go func() {

		if err := srv.ListenAndServe(); err != nil {
			slog.Error("Failed to set udp listener:", err)
			panic(err)
		}

	}()

	slog.Info("Ready for foward notifies on port", "port", config.ServerPort)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	slog.Error("Signal received, stopping", "sig", s)
	srv.Shutdown()
}
