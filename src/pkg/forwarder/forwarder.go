package forwarder

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/dgraph-io/ristretto"
	layers "github.com/google/gopacket/layers"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

type Forwarder interface {
	FetchDNSRecord(ctx context.Context, dnsReq *layers.DNS) (layers.DNS, error)
}

type Service struct {
	res   *net.Resolver
	cache *ristretto.Cache
}

func ProvideService(config util.AppConfig) (Forwarder, error) {

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

	return Service{
		res: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, fmt.Sprintf("%s:%d", net.ParseIP(config.ResolverAddr), config.ResolverPort))
			},
		},
		cache: cache,
	}, nil
}

func (s Service) FetchDNSRecord(ctx context.Context, dnsReq *layers.DNS) (layers.DNS, error) {

	dnsResp := layers.DNS{
		ID: dnsReq.ID,
		QR: true,
		AA: true,
		RD: true,
		RA: true,
	}

	// Serialize the DNS response packet
	for _, q := range dnsReq.Questions {
		records, found := s.cache.Get(q.Name)
		if !found {
			records, count, err := s.forwardDNS(ctx, dnsReq)
			if err != nil {
				return layers.DNS{}, err
			}
			// util function that returns a layer dns and add parameters to it that are manually set
			// resp := createDNSResponse(id, records, count) response
			dnsResp.Answers = records
			dnsResp.ANCount = uint16(count)
			dnsResp.OpCode = layers.DNSOpCodeQuery
			dnsResp.ResponseCode = layers.DNSResponseCodeNoErr

			gobRecs := util.ToGOB(dnsResp)
			s.cache.SetWithTTL(q.Name, gobRecs, 0, 5*time.Second)

			return dnsResp, nil
		}

		cachedResp := util.FromGOB(records.([]byte))
		dnsResp.Answers = cachedResp.Answers
		dnsResp.ANCount = cachedResp.ANCount
		dnsResp.OpCode = layers.DNSOpCodeQuery
		dnsResp.ResponseCode = layers.DNSResponseCodeNoErr
	}
	return dnsResp, nil
}

func (s Service) forwardDNS(ctx context.Context, dnsReq *layers.DNS) ([]layers.DNSResourceRecord, int, error) {
	answers := []layers.DNSResourceRecord{}

	// In reality there are very rarely multiple questions, see https://stackoverflow.com/questions/55092830/how-to-perform-dns-lookup-with-multiple-questions
	for _, q := range dnsReq.Questions {
		// we're only looking upgithi ip4 addresses here
		ips, err := s.res.LookupIP(ctx, "ip4", string(q.Name))
		if err != nil {
			slog.Error("Error when looking up host ip for query", "Query Name:", q.Name)
			return answers, 0, err
		}
		// loop through ip addresses and add as record to answer
		for _, ip := range ips {
			rr := layers.DNSResourceRecord{
				Name:  []byte(q.Name),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				// TTL in minutes here
				TTL: 5,
			}
			rr.IP = ip
			answers = append(answers, rr)
		}
	}
	return answers, len(answers), nil
}
