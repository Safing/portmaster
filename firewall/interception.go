package firewall

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/netenv"

	"github.com/safing/portbase/log"
	"github.com/safing/portbase/modules"
	"github.com/safing/portmaster/firewall/inspection"
	"github.com/safing/portmaster/firewall/interception"
	"github.com/safing/portmaster/network"
	"github.com/safing/portmaster/network/netutils"
	"github.com/safing/portmaster/network/packet"
	"github.com/safing/spn/captain"
	"github.com/safing/spn/sluice"

	// module dependencies
	_ "github.com/safing/portmaster/core/base"
)

var (
	interceptionModule *modules.Module

	packetsAccepted = new(uint64)
	packetsBlocked  = new(uint64)
	packetsDropped  = new(uint64)
	packetsFailed   = new(uint64)
)

func init() {
	interceptionModule = modules.Register("interception", interceptionPrep, interceptionStart, interceptionStop, "base", "updates", "network")

	network.SetDefaultFirewallHandler(defaultHandler)
}

func interceptionPrep() (err error) {
	return prepAPIAuth()
}

func interceptionStart() error {
	startAPIAuth()

	interceptionModule.StartWorker("stat logger", statLogger)
	interceptionModule.StartWorker("packet handler", packetHandler)
	interceptionModule.StartWorker("ports state cleaner", portsInUseCleaner)

	return interception.Start()
}

func interceptionStop() error {
	return interception.Stop()
}

func handlePacket(pkt packet.Packet) {
	if fastTrackedPermit(pkt) {
		return
	}

	traceCtx, tracer := log.AddTracer(context.Background())
	if tracer != nil {
		pkt.SetCtx(traceCtx)
		tracer.Tracef("filter: handling packet: %s", pkt)
	}

	// associate packet to link and handle
	conn, ok := network.GetConnection(pkt.GetConnectionID())
	if ok {
		tracer.Tracef("filter: assigned to connection %s", conn.ID)
	} else {
		conn = network.NewConnectionFromFirstPacket(pkt)
		tracer.Tracef("filter: created new connection %s", conn.ID)
		conn.SetFirewallHandler(initialHandler)
	}

	// handle packet
	conn.HandlePacket(pkt)
}

// fastTrackedPermit quickly permits certain network criticial or internal connections.
func fastTrackedPermit(pkt packet.Packet) (handled bool) {
	meta := pkt.Info()

	switch meta.Protocol {
	case packet.ICMP:
		// Always permit ICMP.
		log.Debugf("accepting ICMP: %s", pkt)
		_ = pkt.PermanentAccept()
		return true

	case packet.ICMPv6:
		// Always permit ICMPv6.
		log.Debugf("accepting ICMPv6: %s", pkt)
		_ = pkt.PermanentAccept()
		return true

	case packet.UDP, packet.TCP:
		switch meta.DstPort {

		case 67, 68, 546, 547:
			// Always allow DHCP, DHCPv6.

			// DHCP and DHCPv6 must be UDP.
			if meta.Protocol != packet.UDP {
				return false
			}

			// DHCP is only valid in local network scopes.
			switch netutils.ClassifyIP(meta.Dst) {
			case netutils.HostLocal, netutils.LinkLocal, netutils.SiteLocal, netutils.LocalMulticast:
			default:
				return false
			}

			// Log and permit.
			log.Debugf("accepting DHCP: %s", pkt)
			_ = pkt.PermanentAccept()
			return true

		case apiPort:
			// Always allow direct access to the Portmaster API.

			// Check if the api port is even set.
			if !apiPortSet {
				return false
			}

			// Portmaster API must be TCP
			if meta.Protocol != packet.TCP {
				return false
			}

			fallthrough
		case 53:
			// Always allow direct local access to own services.
			// DNS is both UDP and TCP.

			// Only allow to own IPs.
			dstIsMe, err := netenv.IsMyIP(meta.Dst)
			if err != nil {
				log.Warningf("filter: failed to check if IP is local: %s", err)
			}
			if !dstIsMe {
				return false
			}

			// Log and permit.
			switch meta.DstPort {
			case 53:
				log.Debugf("accepting local dns: %s", pkt)
			case apiPort:
				log.Debugf("accepting api connection: %s", pkt)
			default:
				return false
			}
			_ = pkt.PermanentAccept()
			return true
		}
	}

	return false
}

func initialHandler(conn *network.Connection, pkt packet.Packet) {
	log.Tracer(pkt.Ctx()).Trace("filter: [initial handler]")

	// check for internal firewall bypass
	ps := getPortStatusAndMarkUsed(pkt.Info().LocalPort())
	if ps.isMe {
		// approve
		conn.Accept("internally approved")
		conn.Internal = true
		// finish
		conn.StopFirewallHandler()
		issueVerdict(conn, pkt, 0, true)
		return
	}

	// reroute dns requests to nameserver
	if conn.Process().Pid != os.Getpid() && pkt.IsOutbound() && pkt.Info().DstPort == 53 && !pkt.Info().Src.Equal(pkt.Info().Dst) {
		conn.Verdict = network.VerdictRerouteToNameserver
		conn.Internal = true
		conn.StopFirewallHandler()
		issueVerdict(conn, pkt, 0, true)
		return
	}

	// check if filtering is enabled
	if !filterEnabled() {
		conn.Inspecting = false
		conn.SetVerdict(network.VerdictAccept, "privacy filter disabled", nil)
		conn.StopFirewallHandler()
		issueVerdict(conn, pkt, 0, true)
		return
	}

	log.Tracer(pkt.Ctx()).Trace("filter: starting decision process")
	DecideOnConnection(pkt.Ctx(), conn, pkt)

	// tunneling
	// TODO: add implementation for forced tunneling
	if pkt.IsOutbound() &&
		captain.ClientReady() &&
		netutils.IPIsGlobal(conn.Entity.IP) &&
		conn.Verdict == network.VerdictAccept {
		// try to tunnel
		err := sluice.AwaitRequest(pkt.Info(), conn.Entity.Domain)
		if err != nil {
			log.Tracer(pkt.Ctx()).Tracef("filter: not tunneling: %s", err)
		} else {
			log.Tracer(pkt.Ctx()).Trace("filter: tunneling request")
			conn.Verdict = network.VerdictRerouteToTunnel
		}
	}

	switch {
	case conn.Inspecting:
		log.Tracer(pkt.Ctx()).Trace("filter: starting inspection")
		// setup inspectors and inspection handler
		inspection.InitializeInspectors(conn, pkt)
		conn.SetFirewallHandler(inspectThenVerdict)
		// execute inspection handler
		inspectThenVerdict(conn, pkt)
	default:
		conn.StopFirewallHandler()
		issueVerdict(conn, pkt, 0, true)
	}

}

func defaultHandler(conn *network.Connection, pkt packet.Packet) {
	issueVerdict(conn, pkt, 0, true)
}

func inspectThenVerdict(conn *network.Connection, pkt packet.Packet) {
	pktVerdict, continueInspection := inspection.RunInspectors(conn, pkt)
	if continueInspection {
		issueVerdict(conn, pkt, pktVerdict, false)
		return
	}

	// we are done with inspecting
	conn.Inspecting = false
	conn.SaveWhenFinished()
	conn.StopFirewallHandler()
	issueVerdict(conn, pkt, 0, true)
}

func issueVerdict(conn *network.Connection, pkt packet.Packet, verdict network.Verdict, allowPermanent bool) {
	// enable permanent verdict
	if allowPermanent && !conn.VerdictPermanent {
		conn.VerdictPermanent = permanentVerdicts()
		if conn.VerdictPermanent {
			conn.SaveWhenFinished()
		}
	}

	// do not allow to circumvent decision: e.g. to ACCEPT packets from a DROP-ed connection
	if verdict < conn.Verdict {
		verdict = conn.Verdict
	}

	var err error
	switch verdict {
	case network.VerdictAccept:
		atomic.AddUint64(packetsAccepted, 1)
		if conn.VerdictPermanent {
			err = pkt.PermanentAccept()
		} else {
			err = pkt.Accept()
		}
	case network.VerdictBlock:
		atomic.AddUint64(packetsBlocked, 1)
		if conn.VerdictPermanent {
			err = pkt.PermanentBlock()
		} else {
			err = pkt.Block()
		}
	case network.VerdictDrop:
		atomic.AddUint64(packetsDropped, 1)
		if conn.VerdictPermanent {
			err = pkt.PermanentDrop()
		} else {
			err = pkt.Drop()
		}
	case network.VerdictRerouteToNameserver:
		err = pkt.RerouteToNameserver()
	case network.VerdictRerouteToTunnel:
		err = pkt.RerouteToTunnel()
	case network.VerdictFailed:
		atomic.AddUint64(packetsFailed, 1)
		err = pkt.Drop()
	default:
		atomic.AddUint64(packetsDropped, 1)
		err = pkt.Drop()
	}

	if err != nil {
		log.Warningf("filter: failed to apply verdict to pkt %s: %s", pkt, err)
	}
}

// func tunnelHandler(pkt packet.Packet) {
// 	tunnelInfo := GetTunnelInfo(pkt.Info().Dst)
// 	if tunnelInfo == nil {
// 		pkt.Block()
// 		return
// 	}
//
// 	entry.CreateTunnel(pkt, tunnelInfo.Domain, tunnelInfo.RRCache.ExportAllARecords())
// 	log.Tracef("filter: rerouting %s to tunnel entry point", pkt)
// 	pkt.RerouteToTunnel()
// 	return
// }

func packetHandler(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt := <-interception.Packets:
			handlePacket(pkt)
		}
	}
}

func statLogger(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(10 * time.Second):
			log.Tracef(
				"filter: packets accepted %d, blocked %d, dropped %d, failed %d",
				atomic.LoadUint64(packetsAccepted),
				atomic.LoadUint64(packetsBlocked),
				atomic.LoadUint64(packetsDropped),
				atomic.LoadUint64(packetsFailed),
			)
			atomic.StoreUint64(packetsAccepted, 0)
			atomic.StoreUint64(packetsBlocked, 0)
			atomic.StoreUint64(packetsDropped, 0)
			atomic.StoreUint64(packetsFailed, 0)
		}
	}
}
