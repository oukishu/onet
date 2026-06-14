package tunnel

import (
	"context"
	"os"
)

// readRaw reads a single raw IP packet from file.
// It checks whether ctx has been canceled before performing the blocking Read,
// and returns the read bytes wrapped in a Packet after performing a deep copy.
func readRaw(ctx context.Context, file *os.File) (Packet, error) {
	select {
	case <-ctx.Done():
		return Packet{}, ctx.Err()
	default:
	}

	// 64 KiB is sufficient to hold any valid IP packet.
	buf := make([]byte, 64*1024)
	n, err := file.Read(buf)
	if err != nil {
		return Packet{}, err
	}

	payload := make([]byte, n)
	copy(payload, buf[:n])
	return RawPacket(payload), nil
}

// writeRaw writes packet.Payload to file.
// It checks whether ctx has been canceled before performing the blocking Write.
func writeRaw(ctx context.Context, file *os.File, packet Packet) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	_, err := file.Write(packet.Payload)
	return err
}