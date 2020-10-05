package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/safing/portmaster/netenv"

	"github.com/safing/portbase/database/record"
	"github.com/safing/portbase/log"
	"github.com/safing/portmaster/intel"
	"github.com/safing/portmaster/network/netutils"
	"github.com/safing/portmaster/network/packet"
	"github.com/safing/portmaster/process"
	"github.com/safing/portmaster/resolver"
)

// FirewallHandler defines the function signature for a firewall handle function
type FirewallHandler func(conn *Connection, pkt packet.Packet)

// Connection describes a distinct physical network connection identified by the IP/Port pair.
type Connection struct { //nolint:maligned // TODO: fix alignment
	record.Base
	sync.Mutex

	ID        string
	Scope     string
	IPVersion packet.IPVersion
	Inbound   bool

	// local endpoint
	IPProtocol packet.IPProtocol
	LocalIP    net.IP
	LocalPort  uint16
	process    *process.Process

	// remote endpoint
	Entity *intel.Entity

	Verdict       Verdict
	Reason        string
	ReasonContext interface{}
	ReasonID      string // format source[:id[:id]] // TODO

	Started          int64
	Ended            int64
	Tunneled         bool
	VerdictPermanent bool
	Inspecting       bool
	Encrypted        bool // TODO
	Internal         bool // Portmaster internal connections are marked in order to easily filter these out in the UI

	pktQueue        chan packet.Packet
	firewallHandler FirewallHandler

	inspectors []Inspector

	saveWhenFinished       bool
	profileRevisionCounter uint64
}

// NewConnectionFromDNSRequest returns a new connection based on the given dns request.
func NewConnectionFromDNSRequest(ctx context.Context, fqdn string, cnames []string, ipVersion packet.IPVersion, localIP net.IP, localPort uint16) *Connection {
	// get Process
	proc, _, err := process.GetProcessByConnection(
		ctx,
		&packet.Info{
			Inbound:  false, // outbound as we are looking for the process of the source address
			Version:  ipVersion,
			Protocol: packet.UDP,
			Src:      localIP,   // source as in the process we are looking for
			SrcPort:  localPort, // source as in the process we are looking for
			Dst:      nil,       // do not record direction
			DstPort:  0,         // do not record direction
		},
	)
	if err != nil {
		log.Debugf("network: failed to find process of dns request for %s: %s", fqdn, err)
		proc = process.GetUnidentifiedProcess(ctx)
	}

	timestamp := time.Now().Unix()
	dnsConn := &Connection{
		Scope: fqdn,
		Entity: &intel.Entity{
			Domain: fqdn,
			CNAME:  cnames,
		},
		process: proc,
		Started: timestamp,
		Ended:   timestamp,
	}
	return dnsConn
}

// NewConnectionFromFirstPacket returns a new connection based on the given packet.
func NewConnectionFromFirstPacket(pkt packet.Packet) *Connection {
	// get Process
	proc, inbound, err := process.GetProcessByConnection(pkt.Ctx(), pkt.Info())
	if err != nil {
		log.Debugf("network: failed to find process of packet %s: %s", pkt, err)
		proc = process.GetUnidentifiedProcess(pkt.Ctx())
	}

	var scope string
	var entity *intel.Entity

	if inbound {

		// inbound connection
		switch netutils.ClassifyIP(pkt.Info().Src) {
		case netutils.HostLocal:
			scope = IncomingHost
		case netutils.LinkLocal, netutils.SiteLocal, netutils.LocalMulticast:
			scope = IncomingLAN
		case netutils.Global, netutils.GlobalMulticast:
			scope = IncomingInternet
		default: // netutils.Invalid
			scope = IncomingInvalid
		}
		entity = &intel.Entity{
			IP:       pkt.Info().Src,
			Protocol: uint8(pkt.Info().Protocol),
			Port:     pkt.Info().SrcPort,
		}

	} else {

		// outbound connection
		entity = &intel.Entity{
			IP:       pkt.Info().Dst,
			Protocol: uint8(pkt.Info().Protocol),
			Port:     pkt.Info().DstPort,
		}

		// check if we can find a domain for that IP
		ipinfo, err := resolver.GetIPInfo(pkt.Info().Dst.String())
		if err == nil {
			lastResolvedDomain := ipinfo.ResolvedDomains.MostRecentDomain()
			if lastResolvedDomain != nil {
				scope = lastResolvedDomain.Domain
				entity.Domain = lastResolvedDomain.Domain
				entity.CNAME = lastResolvedDomain.CNAMEs
				removeOpenDNSRequest(proc.Pid, lastResolvedDomain.Domain)
			}
		}

		// check if destination IP is the captive portal's IP
		portal := netenv.GetCaptivePortal()
		if pkt.Info().Dst.Equal(portal.IP) {
			scope = portal.Domain
			entity.Domain = portal.Domain
		}

		if scope == "" {

			// outbound direct (possibly P2P) connection
			switch netutils.ClassifyIP(pkt.Info().Dst) {
			case netutils.HostLocal:
				scope = PeerHost
			case netutils.LinkLocal, netutils.SiteLocal, netutils.LocalMulticast:
				scope = PeerLAN
			case netutils.Global, netutils.GlobalMulticast:
				scope = PeerInternet
			default: // netutils.Invalid
				scope = PeerInvalid
			}

		}
	}

	return &Connection{
		ID:        pkt.GetConnectionID(),
		Scope:     scope,
		IPVersion: pkt.Info().Version,
		Inbound:   inbound,
		// local endpoint
		IPProtocol: pkt.Info().Protocol,
		LocalIP:    pkt.Info().LocalIP(),
		LocalPort:  pkt.Info().LocalPort(),
		process:    proc,
		// remote endpoint
		Entity: entity,
		// meta
		Started:                time.Now().Unix(),
		Inspecting:             true,
		profileRevisionCounter: proc.Profile().RevisionCnt(),
	}
}

// GetConnection fetches a Connection from the database.
func GetConnection(id string) (*Connection, bool) {
	connsLock.RLock()
	defer connsLock.RUnlock()

	conn, ok := conns[id]
	return conn, ok
}

// AcceptWithContext accepts the connection.
func (conn *Connection) AcceptWithContext(reason string, ctx interface{}) {
	if conn.SetVerdict(VerdictAccept, reason, ctx) {
		log.Infof("filter: granting connection %s, %s", conn, conn.Reason)
	} else {
		log.Warningf("filter: tried to accept %s, but current verdict is %s", conn, conn.Verdict)
	}
}

// Accept is like AcceptWithContext but only accepts a reason.
func (conn *Connection) Accept(reason string) {
	conn.AcceptWithContext(reason, nil)
}

// BlockWithContext blocks the connection.
func (conn *Connection) BlockWithContext(reason string, ctx interface{}) {
	if conn.SetVerdict(VerdictBlock, reason, ctx) {
		log.Infof("filter: blocking connection %s, %s", conn, conn.Reason)
	} else {
		log.Warningf("filter: tried to block %s, but current verdict is %s", conn, conn.Verdict)
	}
}

// Block is like BlockWithContext but does only accepts a reason.
func (conn *Connection) Block(reason string) {
	conn.BlockWithContext(reason, nil)
}

// DropWithContext drops the connection.
func (conn *Connection) DropWithContext(reason string, ctx interface{}) {
	if conn.SetVerdict(VerdictDrop, reason, ctx) {
		log.Infof("filter: dropping connection %s, %s", conn, conn.Reason)
	} else {
		log.Warningf("filter: tried to drop %s, but current verdict is %s", conn, conn.Verdict)
	}
}

// Drop is like DropWithContext but does only accepts a reason.
func (conn *Connection) Drop(reason string) {
	conn.DropWithContext(reason, nil)
}

// DenyWithContext blocks or drops the link depending on the connection direction.
func (conn *Connection) DenyWithContext(reason string, ctx interface{}) {
	if conn.Inbound {
		conn.DropWithContext(reason, ctx)
	} else {
		conn.BlockWithContext(reason, ctx)
	}
}

// Deny is like DenyWithContext but only accepts a reason.
func (conn *Connection) Deny(reason string) {
	conn.DenyWithContext(reason, nil)
}

// FailedWithContext marks the connection with VerdictFailed and stores the reason.
func (conn *Connection) FailedWithContext(reason string, ctx interface{}) {
	if conn.SetVerdict(VerdictFailed, reason, ctx) {
		log.Infof("filter: dropping connection %s because of an internal error: %s", conn, reason)
	} else {
		log.Warningf("filter: tried to drop %s due to error but current verdict is %s", conn, conn.Verdict)
	}
}

// Failed is like FailedWithContext but only accepts a string.
func (conn *Connection) Failed(reason string) {
	conn.FailedWithContext(reason, nil)
}

// SetVerdict sets a new verdict for the connection, making sure it does not interfere with previous verdicts.
func (conn *Connection) SetVerdict(newVerdict Verdict, reason string, reasonCtx interface{}) (ok bool) {
	if newVerdict >= conn.Verdict {
		conn.Verdict = newVerdict
		conn.Reason = reason
		conn.ReasonContext = reasonCtx
		return true
	}
	return false
}

// Process returns the connection's process.
func (conn *Connection) Process() *process.Process {
	return conn.process
}

// SaveWhenFinished marks the connection for saving it after the firewall handler.
func (conn *Connection) SaveWhenFinished() {
	conn.saveWhenFinished = true
}

// Save saves the connection in the storage and propagates the change through the database system.
func (conn *Connection) Save() {
	conn.UpdateMeta()

	if !conn.KeyIsSet() {
		if conn.ID == "" {
			// dns request

			// set key
			conn.SetKey(fmt.Sprintf("network:tree/%d/%s", conn.process.Pid, conn.Scope))
			mapKey := strconv.Itoa(conn.process.Pid) + "/" + conn.Scope

			// save
			dnsConnsLock.Lock()
			dnsConns[mapKey] = conn
			dnsConnsLock.Unlock()
		} else {
			// network connection

			// set key
			conn.SetKey(fmt.Sprintf("network:tree/%d/%s/%s", conn.process.Pid, conn.Scope, conn.ID))

			// save
			connsLock.Lock()
			conns[conn.ID] = conn
			connsLock.Unlock()
		}
	}

	// notify database controller
	dbController.PushUpdate(conn)
}

// delete deletes a link from the storage and propagates the change. Nothing is locked - both the conns map and the connection itself require locking
func (conn *Connection) delete() {
	if conn.ID == "" {
		delete(dnsConns, strconv.Itoa(conn.process.Pid)+"/"+conn.Scope)
	} else {
		delete(conns, conn.ID)
	}

	conn.Meta().Delete()
	dbController.PushUpdate(conn)
}

// UpdateAndCheck updates profiles and checks whether a reevaluation is needed.
func (conn *Connection) UpdateAndCheck() (needsReevaluation bool) {
	p := conn.process.Profile()
	if p == nil {
		return false
	}
	revCnt := p.Update()

	if conn.profileRevisionCounter != revCnt {
		conn.profileRevisionCounter = revCnt
		needsReevaluation = true
	}
	return
}

// SetFirewallHandler sets the firewall handler for this link, and starts a worker to handle the packets.
func (conn *Connection) SetFirewallHandler(handler FirewallHandler) {
	if conn.firewallHandler == nil {
		conn.pktQueue = make(chan packet.Packet, 1000)

		// start handling
		module.StartWorker("packet handler", func(ctx context.Context) error {
			conn.packetHandler()
			return nil
		})
	}
	conn.firewallHandler = handler
}

// StopFirewallHandler unsets the firewall handler and stops the handler worker.
func (conn *Connection) StopFirewallHandler() {
	conn.firewallHandler = nil
	conn.pktQueue <- nil
}

// HandlePacket queues packet of Link for handling
func (conn *Connection) HandlePacket(pkt packet.Packet) {
	conn.Lock()
	defer conn.Unlock()

	// execute handler or verdict
	if conn.firewallHandler != nil {
		conn.pktQueue <- pkt
		// TODO: drop if overflowing?
	} else {
		defaultFirewallHandler(conn, pkt)
	}
}

// packetHandler sequentially handles queued packets
func (conn *Connection) packetHandler() {
	for {
		pkt := <-conn.pktQueue
		if pkt == nil {
			return
		}
		// get handler
		conn.Lock()
		// execute handler or verdict
		if conn.firewallHandler != nil {
			conn.firewallHandler(conn, pkt)
		} else {
			defaultFirewallHandler(conn, pkt)
		}
		conn.Unlock()
		// save does not touch any changing data
		// must not be locked, will deadlock with cleaner functions
		if conn.saveWhenFinished {
			conn.saveWhenFinished = false
			conn.Save()
		}
		// submit trace logs
		log.Tracer(pkt.Ctx()).Submit()
	}
}

// GetInspectors returns the list of inspectors.
func (conn *Connection) GetInspectors() []Inspector {
	return conn.inspectors
}

// SetInspectors sets the list of inspectors.
func (conn *Connection) SetInspectors(new []Inspector) {
	conn.inspectors = new
}

// String returns a string representation of conn.
func (conn *Connection) String() string {
	switch conn.Scope {
	case IncomingHost, IncomingLAN, IncomingInternet, IncomingInvalid:
		return fmt.Sprintf("%s <- %s", conn.process, conn.Entity.IP)
	case PeerHost, PeerLAN, PeerInternet, PeerInvalid:
		return fmt.Sprintf("%s -> %s", conn.process, conn.Entity.IP)
	default:
		return fmt.Sprintf("%s to %s (%s)", conn.process, conn.Entity.Domain, conn.Entity.IP)
	}
}
