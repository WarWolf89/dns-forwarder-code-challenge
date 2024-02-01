package util

import (
	"bytes"
	"encoding/gob"
	"log/slog"

	"github.com/miekg/dns"
)

func ToGOB(dnsResp dns.Msg) []byte {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(dnsResp); err != nil {
		slog.Error("Failed to gob serialize", err)
	}
	return b.Bytes()
}

func FromGOB(ba []byte) *dns.Msg {
	dnsResp := &dns.Msg{}
	d := gob.NewDecoder(bytes.NewReader(ba))
	if err := d.Decode(&dnsResp); err != nil {
		slog.Error("Failed to gob deserialize", err)
	}
	return dnsResp
}
