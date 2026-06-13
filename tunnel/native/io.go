package native

import (
	"context"
	"os"

	"github.com/oukishu/onet/tun"
)

func readRaw(ctx context.Context, file *os.File) (tun.Packet, error) {
	select {
	case <-ctx.Done():
		return tun.Packet{}, ctx.Err()
	default:
	}
	buffer := make([]byte, 64*1024)
	n, err := file.Read(buffer)
	if err != nil {
		return tun.Packet{}, err
	}
	return tun.RawPacket(append([]byte(nil), buffer[:n]...)), nil
}

func writeRaw(ctx context.Context, file *os.File, packet tun.Packet) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	_, err := file.Write(packet.Payload)
	return err
}
