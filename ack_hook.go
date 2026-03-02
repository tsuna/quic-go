package quic

import (
	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/protocol"
)

// PacketNumber is a QUIC packet number.
type PacketNumber = protocol.PacketNumber

// AckHookCallback is called when packets are acknowledged or lost.
// This is used to hook into QUIC's ACK mechanism for custom processing.
type AckHookCallback = ackhandler.AckHookCallback

// SetAckHook injects an ACK hook into the connection.
// The hook will be called when packets are acknowledged or lost.
// This replaces any existing ECN tracker.
//
// Warning: This disables ECN for the connection.
func (c *Conn) SetAckHook(callback AckHookCallback) {
	ackhandler.SetAckHook(c.sentPacketHandler, callback)
}
