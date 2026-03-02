package ackhandler

import (
	"github.com/quic-go/quic-go/internal/protocol"
)

// AckHookCallback is called when packets are acknowledged or lost.
// This is used to hook into QUIC's ACK mechanism for custom processing.
type AckHookCallback interface {
	// OnPacketsAcked is called when packets are acknowledged.
	OnPacketsAcked(packets []protocol.PacketNumber)
	// OnPacketLost is called when a packet is declared lost.
	OnPacketLost(pn protocol.PacketNumber)
}

// SetAckHook injects an ACK hook into a SentPacketHandler.
// This replaces any existing ECN tracker, effectively disabling ECN.
func SetAckHook(sph SentPacketHandler, callback AckHookCallback) {
	if h, ok := sph.(*sentPacketHandler); ok {
		h.ecnTracker = &ackHookHandler{callback: callback}
	}
}

// ackHookHandler implements ecnHandler and invokes callbacks on ACK/loss.
type ackHookHandler struct {
	callback AckHookCallback
}

func (h *ackHookHandler) SentPacket(pn protocol.PacketNumber, ecn protocol.ECN) {
	// No-op: we don't need to track sent packets for our hook
}

func (h *ackHookHandler) Mode() protocol.ECN {
	// Return ECNUnsupported to disable ECN marking
	return protocol.ECNUnsupported
}

func (h *ackHookHandler) HandleNewlyAcked(packets []packetWithPacketNumber, ect0, ect1, ecnce int64) (congested bool) {
	if h.callback != nil && len(packets) > 0 {
		pns := make([]protocol.PacketNumber, len(packets))
		for i, p := range packets {
			pns[i] = p.PacketNumber
		}
		h.callback.OnPacketsAcked(pns)
	}
	return false // no congestion signal from our hook
}

func (h *ackHookHandler) LostPacket(pn protocol.PacketNumber) {
	if h.callback != nil {
		h.callback.OnPacketLost(pn)
	}
}
