package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"atmosphere/internal/model"
)

type BlacklistService struct {
	Resolver *net.Resolver
	Timeout  time.Duration
}

func NewBlacklistService() *BlacklistService {
	return &BlacklistService{
		Resolver: net.DefaultResolver,
		Timeout:  5 * time.Second,
	}
}

var DnsBlacklistZones = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
	"dnsbl.sorbs.net",
	"psbl.surriel.com",
	"cbl.abuseat.org",
}

func (Service *BlacklistService) CheckReputation(TargetIp string) (model.BlacklistResult, error) {
	CleanIp := strings.TrimSpace(TargetIp)
	ParsedIp := net.ParseIP(CleanIp)
	if ParsedIp == nil || ParsedIp.To4() == nil {
		return model.BlacklistResult{}, fmt.Errorf("a valid IPv4 address is required")
	}

	ReversedOctets := ReverseIpOctets(ParsedIp.String())

	var WaitGroup sync.WaitGroup
	var MutexLock sync.Mutex
	var Entries []model.BlacklistEntry
	ListedCount := 0

	for _, ZoneHost := range DnsBlacklistZones {
		WaitGroup.Add(1)
		go func(Zone string) {
			defer WaitGroup.Done()

			Context, CancelFunc := context.WithTimeout(context.Background(), Service.Timeout)
			defer CancelFunc()

			QueryHost := ReversedOctets + "." + Zone
			IpAddresses, LookupError := Service.Resolver.LookupHost(Context, QueryHost)

			IsListed := LookupError == nil && len(IpAddresses) > 0

			MutexLock.Lock()
			Entries = append(Entries, model.BlacklistEntry{
				ZoneName: Zone,
				IsListed: IsListed,
			})
			if IsListed {
				ListedCount++
			}
			MutexLock.Unlock()
		}(ZoneHost)
	}

	WaitGroup.Wait()

	return model.BlacklistResult{
		Ip:           CleanIp,
		Entries:      Entries,
		ListedCount:  ListedCount,
		TotalChecked: len(DnsBlacklistZones),
	}, nil
}

func ReverseIpOctets(IpAddress string) string {
	OctetParts := strings.Split(IpAddress, ".")
	for LeftIndex, RightIndex := 0, len(OctetParts)-1; LeftIndex < RightIndex; LeftIndex, RightIndex = LeftIndex+1, RightIndex-1 {
		OctetParts[LeftIndex], OctetParts[RightIndex] = OctetParts[RightIndex], OctetParts[LeftIndex]
	}
	return strings.Join(OctetParts, ".")
}
