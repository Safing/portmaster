package inspection

import (
	"errors"
	"sort"
	"sync"

	"github.com/safing/portbase/log"
	"github.com/safing/portmaster/network"
	"github.com/safing/portmaster/network/packet"
)

// Registration holds information about and the factory of a registered inspector.
type Registration struct {
	// Name of the Inspector
	Name string

	// Order defines the priority in which the inspector should run. Decrease for higher priority, increase for lower priority. Leave at 0 for no preference.
	Order int

	// Factory creates a new inspector. It may also return a nil inspector, which means that no inspection is desired.
	// Any processing on the packet should only occur on the first call of Inspect. After creating a new Inspector, Inspect is is called with the same connection and packet for actual processing.
	Factory func(conn *network.Connection, pkt packet.Packet) (network.Inspector, error)
}

// Registry is a sortable []*Registration wrapper.
type Registry []*Registration

func (r Registry) Len() int           { return len(r) }
func (r Registry) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r Registry) Less(i, j int) bool { return r[i].Order < r[j].Order }

var (
	inspectorRegistry     []*Registration
	inspectorRegistryLock sync.Mutex
)

// RegisterInspector registers a traffic inspector.
func RegisterInspector(new *Registration) error {
	inspectorRegistryLock.Lock()
	defer inspectorRegistryLock.Unlock()

	if new.Factory == nil {
		return errors.New("missing inspector factory")
	}

	// check if name exists
	for _, r := range inspectorRegistry {
		if new.Name == r.Name {
			return errors.New("already registered")
		}
	}

	// append to list
	inspectorRegistry = append(inspectorRegistry, new)

	// sort
	sort.Stable(Registry(inspectorRegistry))

	return nil
}

// InitializeInspectors initializes all applicable inspectors for the connection.
func InitializeInspectors(conn *network.Connection, pkt packet.Packet) {
	inspectorRegistryLock.Lock()
	defer inspectorRegistryLock.Unlock()

	connInspectors := make([]network.Inspector, 0, len(inspectorRegistry))
	for _, r := range inspectorRegistry {
		inspector, err := r.Factory(conn, pkt)
		switch {
		case err != nil:
			log.Tracer(pkt.Ctx()).Warningf("failed to initialize inspector %s: %v", r.Name, err)
		case inspector != nil:
			connInspectors = append(connInspectors, inspector)
		}
	}

	conn.SetInspectors(connInspectors)
}

// RunInspectors runs all the applicable inspectors on the given packet of the connection. It returns the first error received by an inspector.
func RunInspectors(conn *network.Connection, pkt packet.Packet) (pktVerdict network.Verdict, continueInspection bool) {
	connInspectors := conn.GetInspectors()
	for i, inspector := range connInspectors {
		// check if slot is active
		if inspector == nil {
			continue
		}

		// run inspector
		inspectorPktVerdict, proceed, err := inspector.Inspect(conn, pkt)
		if err != nil {
			log.Tracer(pkt.Ctx()).Warningf("inspector %s failed: %s", inspector.Name(), err)
		}
		// merge
		if inspectorPktVerdict > pktVerdict {
			pktVerdict = inspectorPktVerdict
		}
		if proceed {
			continueInspection = true
		}

		// destroy if finished or failed
		if !proceed || err != nil {
			err = inspector.Destroy()
			if err != nil {
				log.Tracer(pkt.Ctx()).Debugf("inspector %s failed to destroy: %s", inspector.Name(), err)
			}
			connInspectors[i] = nil
		}
	}

	return pktVerdict, continueInspection
}
