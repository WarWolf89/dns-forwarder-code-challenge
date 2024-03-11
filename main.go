package main

import (
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

	killChan := make(chan os.Signal, 1)
	signal.Notify(killChan, syscall.SIGINT, syscall.SIGTERM)

	config, err := util.LoadConfig("test_config")
	// exit immediately on non-recoverable(e.g. path issue) config load errors
	if err != nil {
		slog.Warn("Unrecoverable error when loading config file", "error", err)
		os.Exit(1)
	}

	fwder, err := forwarder.ProvideService(*config)
	if err != nil {
		slog.Error("Error creating the fwder service", err)
		// OS exit since this is unrecoverable(e.g. cache setup failure)
		os.Exit(1)
	}

	// register our custom handler for all domains
	dns.HandleFunc(".", fwder.HandleForwarding)

	go func() {
		srv := &dns.Server{Addr: fmt.Sprintf("%s:%d", config.ServerAddr, config.ServerPort), Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			slog.Error("Failed to set udp listener:", err)
			killChan <- syscall.SIGINT
		}
	}()

	slog.Info("Ready for forward notifies on port", "port", config.ServerPort)
	s := <-killChan
	slog.Error("Signal received, stopping", "sig", s)
}
