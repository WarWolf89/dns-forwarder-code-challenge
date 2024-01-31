package udpserver

import (
	"context"
	"log/slog"
	"net"

	"github.com/google/gopacket"

	"github.com/WarWolf89/dns-forwarder-code-challenge/src/pkg/util"
)

type HookFunc func(ctx context.Context, in []byte, buffer gopacket.SerializeBuffer) error

type UDPServer struct {
	connection *net.UDPConn
	buffer     gopacket.SerializeBuffer
}

func ProviderUDPServer(config *util.AppConfig) (*UDPServer, error) {
	// TODO extract to UDP package
	//Listen on UDP Port
	addr := net.UDPAddr{
		Port: config.ServerPort,
		IP:   net.ParseIP(config.ServerAddr),
	}
	u, err := net.ListenUDP("udp", &addr)
	if err != nil {
		slog.Error("Error when starting UDP server", err)
		return nil, err
	}

	return &UDPServer{
		connection: u,
		buffer:     gopacket.NewSerializeBuffer(),
	}, nil
}

func (udps *UDPServer) Run(hook HookFunc) {

	for {
		ctx := context.Background()
		tmp := make([]byte, 1024)
		// no need to handle byte count for buffer, see https://pkg.go.dev/net#PacketConn
		_, sourceAddr, err := udps.connection.ReadFrom(tmp)
		if err != nil {
			slog.Error("Error reading from buffer for DNS query", "err", err)
			continue
		}
		if hook(ctx, tmp, udps.buffer); err != nil {
			slog.Error("Error with hook", err)
			continue
		}

		udps.connection.WriteTo(udps.buffer.Bytes(), sourceAddr)
		udps.buffer.Clear()
	}
}
