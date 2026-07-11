package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type DnsResolveService struct {
	Resolver *net.Resolver
	Timeout  time.Duration
}

func NewDnsResolveService() *DnsResolveService {
	return &DnsResolveService{
		Resolver: net.DefaultResolver,
		Timeout:  4 * time.Second,
	}
}

func (Service *DnsResolveService) ResolveHostname(TargetHost string) (model.DnsLookupResult, error) {
	TrimmedHost := strings.TrimSpace(TargetHost)
	if TrimmedHost == "" {
		return model.DnsLookupResult{}, fmt.Errorf("hostname is required")
	}

	Context, CancelFunc := context.WithTimeout(context.Background(), Service.Timeout)
	defer CancelFunc()

	IpAddresses, LookupError := Service.Resolver.LookupHost(Context, TrimmedHost)
	if LookupError != nil {
		return model.DnsLookupResult{}, LookupError
	}

	return model.DnsLookupResult{
		Hostname:    TrimmedHost,
		ResolvedIps: IpAddresses,
	}, nil
}

func (Service *DnsResolveService) ReverseLookupIp(TargetIp string) (model.ReverseDnsResult, error) {
	TrimmedIp := strings.TrimSpace(TargetIp)
	ParsedIp := net.ParseIP(TrimmedIp)
	if ParsedIp == nil {
		return model.ReverseDnsResult{}, fmt.Errorf("invalid ip address format")
	}

	Context, CancelFunc := context.WithTimeout(context.Background(), Service.Timeout)
	defer CancelFunc()

	Hostnames, LookupError := Service.Resolver.LookupAddr(Context, TrimmedIp)
	if LookupError != nil {
		return model.ReverseDnsResult{}, LookupError
	}

	return model.ReverseDnsResult{
		Ip:        TrimmedIp,
		Hostnames: Hostnames,
	}, nil
}

func (Service *DnsResolveService) CheckCommonPorts(TargetHost string) map[string]bool {
	PortMap := map[string]string{
		"HTTP":  "80",
		"HTTPS": "443",
		"SSH":   "22",
		"FTP":   "21",
	}

	ResultMap := make(map[string]bool)
	for ServiceName, PortNumber := range PortMap {
		Address := net.JoinHostPort(TargetHost, PortNumber)
		Connection, DialError := net.DialTimeout("tcp", Address, 2*time.Second)
		if DialError != nil {
			ResultMap[ServiceName] = false
			continue
		}
		Connection.Close()
		ResultMap[ServiceName] = true
	}

	return ResultMap
}
