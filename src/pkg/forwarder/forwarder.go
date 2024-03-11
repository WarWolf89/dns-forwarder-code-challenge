package forwarder

import (
	"encoding/gob"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

type Service struct {
	resAddr string
	Client  *dns.Client
	cache   *ristretto.Cache
}

func ProvideService(config util.AppConfig) (*Service, error) {

	// need to register the MSG type for the serializer
	gob.Register(dns.Msg{})
	// RR is an interface pointing to the RR_Header,
	// therefore we need to register resolved structs
	gob.Register(&dns.RR_Header{})
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
	return &Service{
		resAddr: fmt.Sprintf("%s:%d", config.ResolverAddr, config.ResolverPort),
		Client: &dns.Client{
			Net: "",
			Dialer: &net.Dialer{
				Timeout:   5 * time.Second, // Timeout for establishing connections
				KeepAlive: 10 * time.Second,
			},
			Timeout: 30 * time.Second,
		},
		cache: cache,
	}, nil
}

func (s Service) fetchDNSRecord(req *dns.Msg) (*dns.Msg, error) {
	// set default ttl to 1 seconds for cache, if not set defaults to 0 which means it never expires
	ttl := uint32(1)
	dnsResp := &dns.Msg{}
	dnsResp.Id = req.Id
	// Serialize the DNS response packet
	for _, q := range req.Question {
		req.RecursionDesired = true
		records, found := s.cache.Get(q.Name)
		if !found {
			remoteResp, _, err := s.Client.Exchange(req, s.resAddr)
			if err != nil {
				return dnsResp.SetReply(req), err
			}

			switch remoteResp.Rcode {
			// There are scenarios where you can get code 0 and an empty array, especially when there's no recursion. We won't bother with that here.
			case 0:
				// iterate through answers, find the shortest ttl, set it as ttl in cache
				ttl = remoteResp.Answer[0].Header().Ttl
				for _, a := range remoteResp.Answer {
					ttlCurrent := a.Header().Ttl
					if ttl > ttlCurrent {
						ttl = ttlCurrent
					}

				}
				// util function that returns a layer dns and add parameters to it that are manually set
				gobRecs := util.ToGOB(*remoteResp)
				dur := time.Duration(ttl) * time.Second
				s.cache.SetWithTTL(q.Name, gobRecs, 1, dur)
				slog.Info("Added positive cache entry for", "domain", q.Name)
				dnsResp = remoteResp
				return dnsResp, nil
			// server fail on remote
			case 2:
				return dnsResp.SetReply(req), fmt.Errorf("remote nameserver error")
			// simplyfying here for every other case
			default:
				return dnsResp.SetReply(req), nil
			}

		}
		cachedResp := util.FromGOB(records.([]byte))
		cachedResp.Id = req.Id
		dnsResp = cachedResp
		slog.Info("Positive cache hit", "domain", req.Question[0].Name, "Type", req.Question[0].Qtype)
	}
	return dnsResp, nil
}
