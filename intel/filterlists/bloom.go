package filterlists

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/thetannerryan/ring"
	"github.com/safing/portbase/database/record"
	"github.com/safing/portbase/log"
)

var defaultFilter = newScopedBloom()

// scopedBloom is a wrapper around a bloomfilter implementation
// providing scoped filters for different entity types.
type scopedBloom struct {
	rw      sync.RWMutex
	domain  *ring.Ring
	asn     *ring.Ring
	country *ring.Ring
	ipv4    *ring.Ring
	ipv6    *ring.Ring
}

func newScopedBloom() *scopedBloom {
	mustInit := func(size int) *ring.Ring {
		f, err := ring.Init(size, bfFalsePositiveRate)
		if err != nil {
			// we panic here as those values cannot be controlled
			// by the user and invalid values shouldn't be
			// in a release anyway.
			panic("Invalid bloom filter parameters!")
		}
		return f
	}
	return &scopedBloom{
		domain:  mustInit(domainBfSize),
		asn:     mustInit(asnBfSize),
		country: mustInit(countryBfSize),
		ipv4:    mustInit(ipv4BfSize),
		ipv6:    mustInit(ipv6BfSize),
	}
}

func (bf *scopedBloom) getBloomForType(entityType string) (*ring.Ring, error) {
	var r *ring.Ring

	switch strings.ToLower(entityType) {
	case "domain":
		r = bf.domain
	case "asn":
		r = bf.asn
	case "ipv4":
		r = bf.ipv4
	case "ipv6":
		r = bf.ipv6
	case "country":
		r = bf.country
	default:
		return nil, fmt.Errorf("unsupported filterlists entity type %q", entityType)
	}

	return r, nil
}

func (bf *scopedBloom) add(scope, value string) {
	bf.rw.RLock()
	defer bf.rw.RUnlock()

	r, err := bf.getBloomForType(scope)
	if err != nil {
		// If we don't have a bloom filter for that scope
		// we are probably running an older version that does
		// not have support for it. We just drop the value
		// as a call to Test() for that scope will always
		// return "true"
		log.Warningf("failed to add unknown entity type %q with value %q", scope, value)
		return
	}

	r.Add([]byte(value))
}

func (bf *scopedBloom) test(scope, value string) bool {
	bf.rw.RLock()
	defer bf.rw.RUnlock()

	r, err := bf.getBloomForType(scope)
	if err != nil {
		log.Warningf("testing for unknown entity type %q", scope)
		return true // simulate a match to the caller
	}

	return r.Test([]byte(value))
}

func (bf *scopedBloom) loadFromCache() error {
	bf.rw.Lock()
	defer bf.rw.Unlock()

	if err := loadBloomFromCache(bf.domain, "domain"); err != nil {
		return err
	}
	if err := loadBloomFromCache(bf.asn, "asn"); err != nil {
		return err
	}
	if err := loadBloomFromCache(bf.country, "country"); err != nil {
		return err
	}
	if err := loadBloomFromCache(bf.ipv4, "ipv4"); err != nil {
		return err
	}
	if err := loadBloomFromCache(bf.ipv6, "ipv6"); err != nil {
		return err
	}

	return nil
}

func (bf *scopedBloom) saveToCache() error {
	bf.rw.RLock()
	defer bf.rw.RUnlock()

	if err := saveBloomToCache(bf.domain, "domain"); err != nil {
		return err
	}
	if err := saveBloomToCache(bf.asn, "asn"); err != nil {
		return err
	}
	if err := saveBloomToCache(bf.country, "country"); err != nil {
		return err
	}
	if err := saveBloomToCache(bf.ipv4, "ipv4"); err != nil {
		return err
	}
	if err := saveBloomToCache(bf.ipv6, "ipv6"); err != nil {
		return err
	}

	return nil
}

func (bf *scopedBloom) replaceWith(other *scopedBloom) {
	bf.rw.Lock()
	defer bf.rw.Unlock()

	other.rw.RLock()
	defer other.rw.RUnlock()

	bf.domain = other.domain
	bf.asn = other.asn
	bf.country = other.country
	bf.ipv4 = other.ipv4
	bf.ipv6 = other.ipv6
}

type bloomFilterRecord struct {
	record.Base
	sync.Mutex

	Filter string
}

// loadBloomFromCache loads the bloom filter stored under scope
// into bf.
func loadBloomFromCache(bf *ring.Ring, scope string) error {
	r, err := cache.Get(makeBloomCacheKey(scope))
	if err != nil {
		return err
	}

	var filterRecord *bloomFilterRecord
	if r.IsWrapped() {
		filterRecord = new(bloomFilterRecord)
		if err := record.Unwrap(r, filterRecord); err != nil {
			return err
		}
	} else {
		var ok bool
		filterRecord, ok = r.(*bloomFilterRecord)
		if !ok {
			return fmt.Errorf("invalid type, expected bloomFilterRecord but got %T", r)
		}
	}

	blob, err := hex.DecodeString(filterRecord.Filter)
	if err != nil {
		return err
	}

	if err := bf.UnmarshalBinary(blob); err != nil {
		return err
	}

	return nil
}

// saveBloomToCache saves the bitset of the bloomfilter bf
// in the cache db.
func saveBloomToCache(bf *ring.Ring, scope string) error {
	blob, err := bf.MarshalBinary()
	if err != nil {
		return err
	}

	filter := hex.EncodeToString(blob)

	r := &bloomFilterRecord{
		Filter: filter,
	}

	r.SetKey(makeBloomCacheKey(scope))

	return cache.Put(r)
}
