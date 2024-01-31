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

func ToGOB(dnsResp layers.DNS) []byte {
	gob.Register(layers.DNS{})
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(dnsResp); err != nil {
		slog.Error("Failed to gob serialize", err)
	}
	return b.Bytes()
}

func FromGOB(ba []byte) layers.DNS {
	gob.Register(layers.DNS{})
	dnsResp := layers.DNS{}
	d := gob.NewDecoder(bytes.NewReader(ba))
	if err := d.Decode(&dnsResp); err != nil {
		slog.Error("Failed to gob deserialize", err)
	}
	return dnsResp
}
