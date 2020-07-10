// +build !server

package netenv

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/godbus/dbus/v5"
)

var (
	dbusConn     *dbus.Conn
	dbusConnLock sync.Mutex
)

func getNameserversFromDbus() ([]Nameserver, error) { //nolint:gocognit // TODO
	// cmdline tool for exploring: gdbus introspect --system --dest org.freedesktop.NetworkManager --object-path /org/freedesktop/NetworkManager

	var nameservers []Nameserver
	var err error

	dbusConnLock.Lock()
	defer dbusConnLock.Unlock()

	if dbusConn == nil {
		dbusConn, err = dbus.SystemBus()
	}
	if err != nil {
		return nil, err
	}

	primaryConnectionVariant, err := getNetworkManagerProperty(dbusConn, dbus.ObjectPath("/org/freedesktop/NetworkManager"), "org.freedesktop.NetworkManager.PrimaryConnection")
	if err != nil {
		return nil, err
	}
	primaryConnection, ok := primaryConnectionVariant.Value().(dbus.ObjectPath)
	if !ok {
		return nil, errors.New("dbus: could not assert type of /org/freedesktop/NetworkManager:org.freedesktop.NetworkManager.PrimaryConnection")
	}

	activeConnectionsVariant, err := getNetworkManagerProperty(dbusConn, dbus.ObjectPath("/org/freedesktop/NetworkManager"), "org.freedesktop.NetworkManager.ActiveConnections")
	if err != nil {
		return nil, err
	}
	activeConnections, ok := activeConnectionsVariant.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, errors.New("dbus: could not assert type of /org/freedesktop/NetworkManager:org.freedesktop.NetworkManager.ActiveConnections")
	}

	sortedConnections := []dbus.ObjectPath{primaryConnection}
	for _, activeConnection := range activeConnections {
		if !objectPathInSlice(activeConnection, sortedConnections) {
			sortedConnections = append(sortedConnections, activeConnection)
		}
	}

	for _, activeConnection := range sortedConnections {

		ip4ConfigVariant, err := getNetworkManagerProperty(dbusConn, activeConnection, "org.freedesktop.NetworkManager.Connection.Active.Ip4Config")
		if err != nil {
			return nil, err
		}
		ip4Config, ok := ip4ConfigVariant.Value().(dbus.ObjectPath)
		if !ok {
			return nil, fmt.Errorf("dbus: could not assert type of %s:org.freedesktop.NetworkManager.Connection.Active.Ip4Config", activeConnection)
		}

		nameserverIP4sVariant, err := getNetworkManagerProperty(dbusConn, ip4Config, "org.freedesktop.NetworkManager.IP4Config.Nameservers")
		if err != nil {
			return nil, err
		}
		nameserverIP4s, ok := nameserverIP4sVariant.Value().([]uint32)
		if !ok {
			return nil, fmt.Errorf("dbus: could not assert type of %s:org.freedesktop.NetworkManager.IP4Config.Nameservers", ip4Config)
		}

		nameserverDomainsVariant, err := getNetworkManagerProperty(dbusConn, ip4Config, "org.freedesktop.NetworkManager.IP4Config.Domains")
		if err != nil {
			return nil, err
		}
		nameserverDomains, ok := nameserverDomainsVariant.Value().([]string)
		if !ok {
			return nil, fmt.Errorf("dbus: could not assert type of %s:org.freedesktop.NetworkManager.IP4Config.Domains", ip4Config)
		}

		nameserverSearchesVariant, err := getNetworkManagerProperty(dbusConn, ip4Config, "org.freedesktop.NetworkManager.IP4Config.Searches")
		if err != nil {
			return nil, err
		}
		nameserverSearches, ok := nameserverSearchesVariant.Value().([]string)
		if !ok {
			return nil, fmt.Errorf("dbus: could not assert type of %s:org.freedesktop.NetworkManager.IP4Config.Searches", ip4Config)
		}

		for _, ip := range nameserverIP4s {
			a := uint8(ip / 16777216)
			b := uint8((ip % 16777216) / 65536)
			c := uint8((ip % 65536) / 256)
			d := uint8(ip % 256)
			nameservers = append(nameservers, Nameserver{
				IP:     net.IPv4(d, c, b, a),
				Search: append(nameserverDomains, nameserverSearches...),
			})
		}

		ip6ConfigVariant, err := getNetworkManagerProperty(dbusConn, activeConnection, "org.freedesktop.NetworkManager.Connection.Active.Ip6Config")
		if err != nil {
			return nil, err
		}
		ip6Config, ok := ip6ConfigVariant.Value().(dbus.ObjectPath)
		if !ok {
			return nil, fmt.Errorf("dbus: could not assert type of %s:org.freedesktop.NetworkManager.Connection.Active.Ip6Config", activeConnection)
		}

		nameserverIP6sVariant, err := getNetworkManagerProperty(dbusConn, ip6Config, "org.freedesktop.NetworkManager.IP6Config.Nameservers")
		if err != nil {
			return nil, err
		}
		nameserverIP6s, ok := nameserverIP6sVariant.Value().([][]byte)
		if !ok {
			return nil, fmt.Errorf("dbus: could not assert type of %s:org.freedesktop.NetworkManager.IP6Config.Nameservers", ip6Config)
		}

		nameserverDomainsVariant, err = getNetworkManagerProperty(dbusConn, ip6Config, "org.freedesktop.NetworkManager.IP6Config.Domains")
		if err != nil {
			return nil, err
		}
		nameserverDomains, ok = nameserverDomainsVariant.Value().([]string)
		if !ok {
			return nil, fmt.Errorf("dbus: could not assert type of %s:org.freedesktop.NetworkManager.IP6Config.Domains", ip6Config)
		}

		nameserverSearchesVariant, err = getNetworkManagerProperty(dbusConn, ip6Config, "org.freedesktop.NetworkManager.IP6Config.Searches")
		if err != nil {
			return nil, err
		}
		nameserverSearches, ok = nameserverSearchesVariant.Value().([]string)
		if !ok {
			return nil, fmt.Errorf("dbus: could not assert type of %s:org.freedesktop.NetworkManager.IP6Config.Searches", ip6Config)
		}

		for _, ip := range nameserverIP6s {
			if len(ip) != 16 {
				return nil, fmt.Errorf("dbus: query returned IPv6 address (%s) with invalid length", ip)
			}
			nameservers = append(nameservers, Nameserver{
				IP:     net.IP(ip),
				Search: append(nameserverDomains, nameserverSearches...),
			})
		}
	}

	return nameservers, nil
}

func getConnectivityStateFromDbus() (OnlineStatus, error) {
	var err error

	dbusConnLock.Lock()
	defer dbusConnLock.Unlock()

	if dbusConn == nil {
		dbusConn, err = dbus.SystemBus()
	}
	if err != nil {
		return 0, err
	}

	connectivityStateVariant, err := getNetworkManagerProperty(dbusConn, dbus.ObjectPath("/org/freedesktop/NetworkManager"), "org.freedesktop.NetworkManager.Connectivity")
	if err != nil {
		return 0, err
	}
	connectivityState, ok := connectivityStateVariant.Value().(uint32)
	if !ok {
		return 0, errors.New("dbus: could not assert type of /org/freedesktop/NetworkManager:org.freedesktop.NetworkManager.Connectivity")
	}

	// NMConnectivityState
	// NM_CONNECTIVITY_UNKNOWN	= 0 Network connectivity is unknown.
	// NM_CONNECTIVITY_NONE = 1 The host is not connected to any network.
	// NM_CONNECTIVITY_PORTAL = 2 The host is behind a captive portal and cannot reach the full Internet.
	// NM_CONNECTIVITY_LIMITED = 3 The host is connected to a network, but does not appear to be able to reach the full Internet.
	// NM_CONNECTIVITY_FULL = 4 The host is connected to a network, and appears to be able to reach the full Internet.

	switch connectivityState {
	case 0:
		return StatusUnknown, nil
	case 1:
		return StatusOffline, nil
	case 2:
		return StatusPortal, nil
	case 3:
		return StatusLimited, nil
	case 4:
		return StatusOnline, nil
	}

	return StatusUnknown, nil
}

func getNetworkManagerProperty(conn *dbus.Conn, objectPath dbus.ObjectPath, property string) (dbus.Variant, error) {
	object := conn.Object("org.freedesktop.NetworkManager", objectPath)
	return object.GetProperty(property)
}

func objectPathInSlice(a dbus.ObjectPath, list []dbus.ObjectPath) bool {
	for _, b := range list {
		if string(b) == string(a) {
			return true
		}
	}
	return false
}
