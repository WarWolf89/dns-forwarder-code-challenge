package forwarder

import (
	"context"
	"encoding/gob"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

type Forwarder interface {
	FetchDNSRecord(ctx context.Context, r *dns.Msg) (*dns.Msg, error)
}

type Service struct {
	resAddr string
	Client  *dns.Client
	cache   *ristretto.Cache
}

func ProvideService(config util.AppConfig) (Forwarder, error) {

	// need to register the MSG type for the serializer
	gob.Register(dns.Msg{})
	// RR is an interface pointing to the RR_Header, therefore we need to register pointers for the header fields
	gob.Register(&dns.CNAME{})
	gob.Register(&dns.A{})
	gob.Register(&dns.OPT{})

	// move to cache layer in pkg, possibly move gob here
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e7,     // number of keys to track frequency of (10M).
		MaxCost:     1 << 30, // maximum cost of cache (1GB).
		BufferItems: 64,      // number of keys per Get buffer.
	})
	if err != nil {
		slog.Error("Error setting up cache", err)
		return nil, err
	}

	if err != nil {
		slog.Error("error dialing resolver", err)
		return nil, err
	}
	return Service{
		resAddr: fmt.Sprintf("%s:%d", config.ResolverAddr, config.ResolverPort),
		Client: &dns.Client{
			Net: "udp",
			Dialer: &net.Dialer{
				Timeout:   5 * time.Second, // Timeout for establishing connections
				KeepAlive: 30 * time.Second,
			},
			Timeout: 10 * time.Second,
		},
		cache: cache,
	}, nil
}

func (s Service) FetchDNSRecord(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	dnsResp := &dns.Msg{}
	// Serialize the DNS response packet
	for _, q := range req.Question {
		records, found := s.cache.Get(q.Name)
		if !found {
			response, _, err := s.Client.Exchange(req, s.resAddr)
			if err != nil {
				return nil, err
			}
			// util function that returns a layer dns and add parameters to it that are manually set
			// resp := createDNSResponse(id, records, count) response

			gobRecs := util.ToGOB(*response)
			s.cache.SetWithTTL(q.Name, gobRecs, 0, 5*time.Second)

			return response, nil
		}

		cachedResp := util.FromGOB(records.([]byte))
		cachedResp.Id = req.Id
		dnsResp = cachedResp
	}
	return dnsResp, nil
}
