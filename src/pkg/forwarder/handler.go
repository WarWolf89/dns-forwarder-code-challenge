package forwarder

import (
	"log/slog"

	"github.com/miekg/dns"
)

func (s Service) HandleForwarding(w dns.ResponseWriter, req *dns.Msg) {
	resp, err := s.fetchDNSRecord(req)

	// resp can't be nil, we reply to the client
	if err := w.WriteMsg(resp); err != nil {
		slog.Error("Error writing message to client", err)
		return
	}

	if err != nil {
		slog.Error("Error when forwarding DNS request for: ", "Request", *req, "Error", err)
		return
	}
	slog.Info("Handled request for", "domain", req.Question, "Header RCODE", resp.MsgHdr.Rcode, "answer", resp.Answer)

}
