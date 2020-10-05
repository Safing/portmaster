package encryption

import (
	"github.com/safing/portmaster/firewall/inspection"
	"github.com/safing/portmaster/network"
	"github.com/safing/portmaster/network/packet"
)

// Detector detects if a connection is encrypted.
type Detector struct{}

// Name implements the inspection interface.
func (d *Detector) Name() string {
	return "Encryption Detection"
}

// Inspect implements the inspection interface.
func (d *Detector) Inspect(conn *network.Connection, pkt packet.Packet) (pktVerdict network.Verdict, proceed bool, err error) {
	if !conn.Inbound {
		switch conn.Entity.Port {
		case 443, 465, 993, 995:
			conn.Encrypted = true
			conn.SaveWhenFinished()
		}
	}

	return network.VerdictUndecided, false, nil
}

// Destroy implements the destroy interface.
func (d *Detector) Destroy() error {
	return nil
}

// DetectorFactory is a primitive detection method that runs within the factory only.
func DetectorFactory(conn *network.Connection, pkt packet.Packet) (network.Inspector, error) {
	return &Detector{}, nil
}

// Register registers the encryption detection inspector with the inspection framework.
func init() {
	err := inspection.RegisterInspector(&inspection.Registration{
		Name:    "Encryption Detection",
		Order:   0,
		Factory: DetectorFactory,
	})
	if err != nil {
		panic(err)
	}
}
