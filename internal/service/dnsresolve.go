package service

import (
	"context"
	"fmt"
	"net"
	"sort"
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

func (Service *DnsResolveService) CheckPortsDetailed(TargetHost string) model.PortCheckResult {
	PortDefinitions := []struct {
		Name string
		Port int
	}{
		{"FTP", 21},
		{"SSH", 22},
		{"Telnet", 23},
		{"SMTP", 25},
		{"DNS", 53},
		{"HTTP", 80},
		{"POP3", 110},
		{"IMAP", 143},
		{"HTTPS", 443},
		{"SMTPS", 465},
		{"IMAPS", 993},
		{"POP3S", 995},
		{"MySQL", 3306},
		{"RDP", 3389},
		{"PostgreSQL", 5432},
		{"Redis", 6379},
		{"HTTP-Alt", 8080},
		{"HTTPS-Alt", 8443},
	}

	var PortEntries []model.PortCheckEntry
	for _, Definition := range PortDefinitions {
		Address := net.JoinHostPort(TargetHost, fmt.Sprintf("%d", Definition.Port))
		StartTime := time.Now()
		Connection, DialError := net.DialTimeout("tcp", Address, 2*time.Second)
		LatencyMs := time.Since(StartTime).Milliseconds()

		IsOpen := DialError == nil
		if IsOpen {
			Connection.Close()
		}

		PortEntries = append(PortEntries, model.PortCheckEntry{
			ServiceName: Definition.Name,
			Port:        Definition.Port,
			IsOpen:      IsOpen,
			LatencyMs:   LatencyMs,
		})
	}

	return model.PortCheckResult{Hostname: TargetHost, Ports: PortEntries}
}

func (Service *DnsResolveService) LookupFullRecords(TargetHost string) (model.DnsRecordsResult, error) {
	TrimmedHost := strings.TrimSpace(TargetHost)
	if TrimmedHost == "" {
		return model.DnsRecordsResult{}, fmt.Errorf("hostname is required")
	}

	Context, CancelFunc := context.WithTimeout(context.Background(), Service.Timeout)
	defer CancelFunc()

	Result := model.DnsRecordsResult{Hostname: TrimmedHost}

	IpAddresses, HostLookupError := Service.Resolver.LookupHost(Context, TrimmedHost)
	if HostLookupError == nil {
		for _, IpAddress := range IpAddresses {
			ParsedIp := net.ParseIP(IpAddress)
			if ParsedIp == nil {
				continue
			}
			if ParsedIp.To4() != nil {
				Result.ARecords = append(Result.ARecords, IpAddress)
			} else {
				Result.AaaaRecords = append(Result.AaaaRecords, IpAddress)
			}
		}
	}

	MxRecords, MxLookupError := Service.Resolver.LookupMX(Context, TrimmedHost)
	if MxLookupError == nil {
		for _, MxRecord := range MxRecords {
			Result.MxRecords = append(Result.MxRecords, fmt.Sprintf("%s (priority %d)", strings.TrimSuffix(MxRecord.Host, "."), MxRecord.Pref))
		}
	}

	TxtRecords, TxtLookupError := Service.Resolver.LookupTXT(Context, TrimmedHost)
	if TxtLookupError == nil {
		Result.TxtRecords = TxtRecords
	}

	NsRecords, NsLookupError := Service.Resolver.LookupNS(Context, TrimmedHost)
	if NsLookupError == nil {
		for _, NsRecord := range NsRecords {
			Result.NsRecords = append(Result.NsRecords, strings.TrimSuffix(NsRecord.Host, "."))
		}
	}

	CnameRecord, CnameLookupError := Service.Resolver.LookupCNAME(Context, TrimmedHost)
	if CnameLookupError == nil {
		Result.CnameRecord = strings.TrimSuffix(CnameRecord, ".")
	}

	if len(Result.ARecords) == 0 && len(Result.AaaaRecords) == 0 && len(Result.MxRecords) == 0 &&
		len(Result.TxtRecords) == 0 && len(Result.NsRecords) == 0 && Result.CnameRecord == "" {
		return Result, fmt.Errorf("no dns records found for host")
	}

	return Result, nil
}

func (Service *DnsResolveService) RunPing(TargetHost string) (model.PingResult, error) {
	TrimmedHost := strings.TrimSpace(TargetHost)
	if TrimmedHost == "" {
		return model.PingResult{}, fmt.Errorf("target host is required")
	}

	Context, CancelFunc := context.WithTimeout(context.Background(), Service.Timeout)
	defer CancelFunc()

	ResolvedIp := TrimmedHost
	if net.ParseIP(TrimmedHost) == nil {
		IpAddresses, LookupError := Service.Resolver.LookupHost(Context, TrimmedHost)
		if LookupError != nil || len(IpAddresses) == 0 {
			return model.PingResult{}, fmt.Errorf("unable to resolve host")
		}
		ResolvedIp = IpAddresses[0]
	}

	const AttemptCount = 4
	var Attempts []model.PingAttempt
	var LatencySamples []int64
	SuccessCount := 0

	for SequenceIndex := 1; SequenceIndex <= AttemptCount; SequenceIndex++ {
		StartTime := time.Now()
		Connection, DialError := net.DialTimeout("tcp", net.JoinHostPort(ResolvedIp, "80"), 2*time.Second)
		LatencyMs := time.Since(StartTime).Milliseconds()

		Success := DialError == nil
		if Success {
			Connection.Close()
			SuccessCount++
			LatencySamples = append(LatencySamples, LatencyMs)
		}

		Attempts = append(Attempts, model.PingAttempt{
			Sequence:  SequenceIndex,
			Success:   Success,
			LatencyMs: LatencyMs,
		})
	}

	MinLatency, MaxLatency, AvgLatency := ComputeLatencyStats(LatencySamples)
	PacketLoss := 100.0 * float64(AttemptCount-SuccessCount) / float64(AttemptCount)

	return model.PingResult{
		Hostname:     TrimmedHost,
		ResolvedIp:   ResolvedIp,
		Attempts:     Attempts,
		MinLatencyMs: MinLatency,
		MaxLatencyMs: MaxLatency,
		AvgLatencyMs: AvgLatency,
		PacketLoss:   PacketLoss,
	}, nil
}

func ComputeLatencyStats(Samples []int64) (int64, int64, int64) {
	if len(Samples) == 0 {
		return 0, 0, 0
	}

	SortedSamples := append([]int64{}, Samples...)
	sort.Slice(SortedSamples, func(FirstIndex, SecondIndex int) bool {
		return SortedSamples[FirstIndex] < SortedSamples[SecondIndex]
	})

	var Total int64
	for _, Sample := range SortedSamples {
		Total += Sample
	}

	return SortedSamples[0], SortedSamples[len(SortedSamples)-1], Total / int64(len(SortedSamples))
}
