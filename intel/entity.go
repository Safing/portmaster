package intel

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/safing/portbase/log"
	"github.com/safing/portmaster/intel/filterlists"
	"github.com/safing/portmaster/intel/geoip"
	"github.com/safing/portmaster/network/netutils"
	"github.com/safing/portmaster/status"
	"golang.org/x/net/publicsuffix"
)

// Entity describes a remote endpoint in many different ways.
// It embeddes a sync.Mutex but none of the endpoints own
// functions performs locking. The caller MUST ENSURE
// proper locking and synchronization when accessing
// any properties of Entity.
type Entity struct {
	sync.Mutex

	// lists exist for most entity information and
	// we need to know which one we loaded
	domainListLoaded      bool
	ipListLoaded          bool
	countryListLoaded     bool
	asnListLoaded         bool
	reverseResolveEnabled bool
	resolveSubDomainLists bool
	checkCNAMEs           bool

	// Protocol is the protocol number used by the connection.
	Protocol uint8

	// Port is the remote port of the connection
	Port uint16

	// dstPort is the destination port of the connection
	dstPort uint16

	// Domain is the target domain of the connection.
	Domain string

	// ReverseDomain is the domain the IP address points to. This is only
	// resolved and populated when needed.
	ReverseDomain string

	// CNAME is a list of domain names that have been
	// resolved for Domain.
	CNAME []string

	// IP is the IP address of the connection. If domain is
	// set, IP has been resolved by following all CNAMEs.
	IP net.IP

	// Country holds the country the IP address (ASN) is
	// located in.
	Country string

	// ASN holds the autonomous system number of the IP.
	ASN uint

	location *geoip.Location

	// BlockedByLists holds list source IDs that
	// are used to block the entity.
	BlockedByLists []string

	// BlockedEntities holds a list of entities that
	// have been blocked. Values can be used as a key
	// for the ListOccurences map.
	BlockedEntities []string

	// ListOccurences is a map that matches an entity (Domain, IPs, ASN, Country, Sub-domain)
	// to a list of sources where the entity has been observed in.
	ListOccurences map[string][]string

	// we only load each data above at most once
	fetchLocationOnce  sync.Once
	reverseResolveOnce sync.Once
	loadDomainListOnce sync.Once
	loadIPListOnce     sync.Once
	loadCoutryListOnce sync.Once
	loadAsnListOnce    sync.Once
}

// Init initializes the internal state and returns the entity.
func (e *Entity) Init() *Entity {
	// for backwards compatibility, remove that one
	return e
}

// SetDstPort sets the destination port.
func (e *Entity) SetDstPort(dstPort uint16) {
	e.dstPort = dstPort
}

// DstPort returns the destination port.
func (e *Entity) DstPort() uint16 {
	return e.dstPort
}

// FetchData fetches additional information, meant to be called before persisting an entity record.
func (e *Entity) FetchData(ctx context.Context) {
	e.getLocation(ctx)
	e.getLists(ctx)
}

// ResetLists resets the current list data and forces
// all list sources to be re-acquired when calling GetLists().
func (e *Entity) ResetLists() {
	// TODO(ppacher): our actual goal is to reset the domain
	// list right now so we could be more efficient by keeping
	// the other lists around.

	e.BlockedByLists = nil
	e.BlockedEntities = nil
	e.ListOccurences = nil

	e.domainListLoaded = false
	e.ipListLoaded = false
	e.countryListLoaded = false
	e.asnListLoaded = false
	e.resolveSubDomainLists = false
	e.checkCNAMEs = false
	e.loadDomainListOnce = sync.Once{}
	e.loadIPListOnce = sync.Once{}
	e.loadCoutryListOnce = sync.Once{}
	e.loadAsnListOnce = sync.Once{}
}

// ResolveSubDomainLists enables or disables list lookups for
// sub-domains.
func (e *Entity) ResolveSubDomainLists(ctx context.Context, enabled bool) {
	if e.domainListLoaded {
		log.Tracer(ctx).Warningf("intel/filterlists: tried to change sub-domain resolving for %s but lists are already fetched", e.Domain)
	}
	e.resolveSubDomainLists = enabled
}

// EnableCNAMECheck enables or disables list lookups for
// entity CNAMEs.
func (e *Entity) EnableCNAMECheck(ctx context.Context, enabled bool) {
	if e.domainListLoaded {
		log.Tracer(ctx).Warningf("intel/filterlists: tried to change CNAME resolving for %s but lists are already fetched", e.Domain)
	}
	e.checkCNAMEs = enabled
}

// CNAMECheckEnabled returns true if the entities CNAMEs should
// also be checked.
func (e *Entity) CNAMECheckEnabled() bool {
	return e.checkCNAMEs
}

// Domain and IP

// EnableReverseResolving enables reverse resolving the domain from the IP on demand.
func (e *Entity) EnableReverseResolving() {
	e.reverseResolveEnabled = true
}

func (e *Entity) reverseResolve(ctx context.Context) {
	e.reverseResolveOnce.Do(func() {
		// need IP!
		if e.IP == nil {
			return
		}

		// reverse resolve
		if reverseResolver == nil {
			return
		}
		// TODO: security level
		domain, err := reverseResolver(ctx, e.IP.String(), status.SecurityLevelNormal)
		if err != nil {
			log.Tracer(ctx).Warningf("intel: failed to resolve IP %s: %s", e.IP, err)
			return
		}
		e.ReverseDomain = domain
	})
}

// GetDomain returns the domain and whether it is set.
func (e *Entity) GetDomain(ctx context.Context, mayUseReverseDomain bool) (string, bool) {
	if mayUseReverseDomain && e.reverseResolveEnabled {
		e.reverseResolve(ctx)

		if e.ReverseDomain == "" {
			return "", false
		}
		return e.ReverseDomain, true
	}

	if e.Domain == "" {
		return "", false
	}
	return e.Domain, true
}

// GetIP returns the IP and whether it is set.
func (e *Entity) GetIP() (net.IP, bool) {
	if e.IP == nil {
		return nil, false
	}
	return e.IP, true
}

// Location

func (e *Entity) getLocation(ctx context.Context) {
	e.fetchLocationOnce.Do(func() {
		// need IP!
		if e.IP == nil {
			return
		}

		// get location data
		loc, err := geoip.GetLocation(e.IP)
		if err != nil {
			log.Tracer(ctx).Warningf("intel: failed to get location data for %s: %s", e.IP, err)
			return
		}
		e.location = loc
		e.Country = loc.Country.ISOCode
		e.ASN = loc.AutonomousSystemNumber
	})
}

// GetLocation returns the raw location data and whether it is set.
func (e *Entity) GetLocation(ctx context.Context) (*geoip.Location, bool) {
	e.getLocation(ctx)

	if e.location == nil {
		return nil, false
	}
	return e.location, true
}

// GetCountry returns the two letter ISO country code and whether it is set.
func (e *Entity) GetCountry(ctx context.Context) (string, bool) {
	e.getLocation(ctx)

	if e.Country == "" {
		return "", false
	}
	return e.Country, true
}

// GetASN returns the AS number and whether it is set.
func (e *Entity) GetASN(ctx context.Context) (uint, bool) {
	e.getLocation(ctx)

	if e.ASN == 0 {
		return 0, false
	}
	return e.ASN, true
}

// Lists
func (e *Entity) getLists(ctx context.Context) {
	e.getDomainLists(ctx)
	e.getASNLists(ctx)
	e.getIPLists(ctx)
	e.getCountryLists(ctx)
}

func (e *Entity) mergeList(key string, list []string) {
	if len(list) == 0 {
		return
	}

	if e.ListOccurences == nil {
		e.ListOccurences = make(map[string][]string)
	}

	e.ListOccurences[key] = mergeStringList(e.ListOccurences[key], list)
}

func (e *Entity) getDomainLists(ctx context.Context) {
	if e.domainListLoaded {
		return
	}

	domain, ok := e.GetDomain(ctx, false /* mayUseReverseDomain */)
	if !ok {
		return
	}

	var err error
	e.loadDomainListOnce.Do(func() {
		var domainsToInspect = []string{domain}

		if e.checkCNAMEs {
			log.Tracer(ctx).Tracef("intel: CNAME filtering enabled, checking %v too", e.CNAME)
			domainsToInspect = append(domainsToInspect, e.CNAME...)
		}

		var domains []string
		if e.resolveSubDomainLists {
			for _, domain := range domainsToInspect {
				subdomains := splitDomain(domain)
				domains = append(domains, subdomains...)
			}
		} else {
			domains = domainsToInspect
		}

		domains = makeDistinct(domains)

		for _, d := range domains {
			log.Tracer(ctx).Tracef("intel: loading domain list for %s", d)
			var list []string
			list, err = filterlists.LookupDomain(d)
			if err != nil {
				log.Tracer(ctx).Errorf("intel: failed to get domain blocklists for %s: %s", d, err)
				return
			}

			e.mergeList(d, list)
		}
		e.domainListLoaded = true
	})

	if err != nil {
		e.loadDomainListOnce = sync.Once{}
	}
}

func splitDomain(domain string) []string {
	domain = strings.Trim(domain, ".")
	suffix, _ := publicsuffix.PublicSuffix(domain)
	if suffix == domain {
		return []string{domain}
	}

	domainWithoutSuffix := domain[:len(domain)-len(suffix)]
	domainWithoutSuffix = strings.Trim(domainWithoutSuffix, ".")

	splitted := strings.FieldsFunc(domainWithoutSuffix, func(r rune) bool {
		return r == '.'
	})

	domains := make([]string, 0, len(splitted))
	for idx := range splitted {

		d := strings.Join(splitted[idx:], ".") + "." + suffix
		if d[len(d)-1] != '.' {
			d += "."
		}
		domains = append(domains, d)
	}
	return domains
}

func (e *Entity) getASNLists(ctx context.Context) {
	if e.asnListLoaded {
		return
	}

	asn, ok := e.GetASN(ctx)
	if !ok {
		return
	}

	log.Tracer(ctx).Tracef("intel: loading ASN list for %d", asn)
	e.loadAsnListOnce.Do(func() {
		asnStr := fmt.Sprintf("%d", asn)
		list, err := filterlists.LookupASNString(asnStr)
		if err != nil {
			log.Tracer(ctx).Errorf("intel: failed to get ASN blocklist for %d: %s", asn, err)
			e.loadAsnListOnce = sync.Once{}
			return
		}

		e.asnListLoaded = true
		e.mergeList(asnStr, list)
	})
}

func (e *Entity) getCountryLists(ctx context.Context) {
	if e.countryListLoaded {
		return
	}

	country, ok := e.GetCountry(ctx)
	if !ok {
		return
	}

	log.Tracer(ctx).Tracef("intel: loading country list for %s", country)
	e.loadCoutryListOnce.Do(func() {
		list, err := filterlists.LookupCountry(country)
		if err != nil {
			log.Tracer(ctx).Errorf("intel: failed to load country blocklist for %s: %s", country, err)
			e.loadCoutryListOnce = sync.Once{}
			return
		}

		e.countryListLoaded = true
		e.mergeList(country, list)
	})
}

func (e *Entity) getIPLists(ctx context.Context) {
	if e.ipListLoaded {
		return
	}

	ip, ok := e.GetIP()
	if !ok {
		return
	}

	if ip == nil {
		return
	}

	// only load lists for IP addresses that are classified as global.
	if netutils.ClassifyIP(ip) != netutils.Global {
		return
	}

	log.Tracer(ctx).Tracef("intel: loading IP list for %s", ip)
	e.loadIPListOnce.Do(func() {
		list, err := filterlists.LookupIP(ip)

		if err != nil {
			log.Tracer(ctx).Errorf("intel: failed to get IP blocklist for %s: %s", ip.String(), err)
			e.loadIPListOnce = sync.Once{}
			return
		}
		e.ipListLoaded = true
		e.mergeList(ip.String(), list)
	})
}

// LoadLists searches all filterlists for all occurrences of
// this entity.
func (e *Entity) LoadLists(ctx context.Context) bool {
	e.getLists(ctx)

	return e.ListOccurences != nil
}

// MatchLists matches the entities lists against a slice
// of source IDs and  updates various entity properties
// like BlockedByLists, ListOccurences and BlockedEntitites.
func (e *Entity) MatchLists(lists []string) bool {
	e.BlockedByLists = nil
	e.BlockedEntities = nil

	lm := makeMap(lists)
	for key, keyLists := range e.ListOccurences {
		for _, keyListID := range keyLists {
			if _, ok := lm[keyListID]; ok {
				e.BlockedByLists = append(e.BlockedByLists, keyListID)
				e.BlockedEntities = append(e.BlockedEntities, key)
			}
		}
	}

	e.BlockedByLists = makeDistinct(e.BlockedByLists)
	e.BlockedEntities = makeDistinct(e.BlockedEntities)

	return len(e.BlockedByLists) > 0
}

// ListBlockReason returns the block reason for this entity.
func (e *Entity) ListBlockReason() ListBlockReason {
	blockedBy := make([]ListMatch, len(e.BlockedEntities))

	lm := makeMap(e.BlockedByLists)

	for idx, blockedEntity := range e.BlockedEntities {
		if entityLists, ok := e.ListOccurences[blockedEntity]; ok {
			var activeLists []string
			var inactiveLists []string

			for _, l := range entityLists {
				if _, ok := lm[l]; ok {
					activeLists = append(activeLists, l)
				} else {
					inactiveLists = append(inactiveLists, l)
				}
			}

			blockedBy[idx] = ListMatch{
				Entity:        blockedEntity,
				ActiveLists:   activeLists,
				InactiveLists: inactiveLists,
			}
		}
	}

	return blockedBy
}

func mergeStringList(a, b []string) []string {
	listMap := make(map[string]struct{})
	for _, s := range a {
		listMap[s] = struct{}{}
	}
	for _, s := range b {
		listMap[s] = struct{}{}
	}

	res := make([]string, 0, len(listMap))
	for s := range listMap {
		res = append(res, s)
	}
	sort.Strings(res)
	return res
}

func makeDistinct(slice []string) []string {
	m := make(map[string]struct{}, len(slice))
	result := make([]string, 0, len(slice))

	for _, v := range slice {
		if _, ok := m[v]; ok {
			continue
		}

		m[v] = struct{}{}
		result = append(result, v)
	}

	return result
}

func makeMap(slice []string) map[string]struct{} {
	lm := make(map[string]struct{})
	for _, v := range slice {
		lm[v] = struct{}{}
	}
	return lm
}
