package forwarder

import (
	"context"
	"log/slog"
	"net"

	"github.com/dgraph-io/ristretto"
	layers "github.com/google/gopacket/layers"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

func ForwardDNS(ctx *context.Context, dnsReq *layers.DNS, r *net.Resolver) ([]layers.DNSResourceRecord, int, error) {
	answers := []layers.DNSResourceRecord{}

	// In reality there are very rarely multiple questions, see https://stackoverflow.com/questions/55092830/how-to-perform-dns-lookup-with-multiple-questions
	for _, q := range dnsReq.Questions {
		// we're only looking upgithi ip4 addresses here
		ips, err := r.LookupIP(*ctx, "ip4", string(q.Name))
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
				TTL:   60,
			}
			rr.IP = ip
			answers = append(answers, rr)
		}
	}
	return answers, len(answers), nil
}

func FetchDNSRecord(ctx *context.Context, cache ristretto.Cache, dnsReq *layers.DNS, r *net.Resolver) (layers.DNS, error) {

	dnsResp := layers.DNS{
		ID: dnsReq.ID,
		QR: true,
		AA: true,
		RD: true,
		RA: true,
	}

	// Serialize the DNS response packet
	for _, q := range dnsReq.Questions {
		records, found := cache.Get(q.Name)
		if !found {
			records, count, err := ForwardDNS(ctx, dnsReq, r)
			if err != nil {
				return layers.DNS{}, err
			}

			dnsResp.Answers = records
			dnsResp.ANCount = uint16(count)
			dnsResp.OpCode = layers.DNSOpCodeQuery
			dnsResp.ResponseCode = layers.DNSResponseCodeNoErr

			gobRecs := util.ToGOB(dnsResp)
			cache.Set(q.Name, gobRecs, 0)

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
