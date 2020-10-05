package network

import (
	"github.com/safing/portmaster/network/packet"
)

// Inspector is a connection inspection interface for detailed analysis of network connections.
type Inspector interface {
	// Name returns the name of the inspector.
	Name() string

	// Inspect is called for every packet. It returns whether it wants to proceed with processing and possibly an error.
	Inspect(conn *Connection, pkt packet.Packet) (pktVerdict Verdict, proceed bool, err error)

	// Destroy cancels the inspector and frees all resources.
	// It is called as soon as Inspect returns proceed=false, an error occures, or if the inspection has ended early.
	Destroy() error
}
