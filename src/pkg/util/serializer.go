package util

import (
	"bytes"
	"encoding/gob"
	"log/slog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func CastToDNSLayer(pkt gopacket.Packet) *layers.DNS {
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

func ToGOB(rr []layers.DNSResourceRecord) []byte {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(rr); err != nil {
		slog.Error("Failed to gob serialize", err)
	}
	return b.Bytes()
}

func FromGOB(ba []byte) []layers.DNSResourceRecord {
	rr := []layers.DNSResourceRecord{}
	b := bytes.Buffer{}
	d := gob.NewDecoder(&b)
	if err := d.Decode(&rr); err != nil {
		slog.Error("Failed to gob deserialize", err)
	}
	return rr
}
