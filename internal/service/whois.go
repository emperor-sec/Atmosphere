package service

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type WhoisService struct {
	Timeout time.Duration
}

func NewWhoisService() *WhoisService {
	return &WhoisService{Timeout: 6 * time.Second}
}

var TldWhoisServers = map[string]string{
	"com":    "whois.verisign-grs.com",
	"net":    "whois.verisign-grs.com",
	"org":    "whois.pir.org",
	"io":     "whois.nic.io",
	"co":     "whois.nic.co",
	"dev":    "whois.nic.google",
	"app":    "whois.nic.google",
	"info":   "whois.afilias.net",
	"biz":    "whois.nic.biz",
	"us":     "whois.nic.us",
	"me":     "whois.nic.me",
	"tv":     "whois.nic.tv",
	"cc":     "whois.nic.cc",
	"xyz":    "whois.nic.xyz",
	"id":     "whois.id",
	"sg":     "whois.sgnic.sg",
	"uk":     "whois.nic.uk",
	"ai":     "whois.nic.ai",
}

func (Service *WhoisService) LookupDomain(TargetDomain string) (model.WhoisResult, error) {
	CleanDomain := strings.ToLower(strings.TrimSpace(TargetDomain))
	CleanDomain = strings.TrimPrefix(CleanDomain, "https://")
	CleanDomain = strings.TrimPrefix(CleanDomain, "http://")
	CleanDomain = strings.TrimSuffix(CleanDomain, "/")
	if CleanDomain == "" {
		return model.WhoisResult{}, fmt.Errorf("target domain is required")
	}

	DomainParts := strings.Split(CleanDomain, ".")
	if len(DomainParts) < 2 {
		return model.WhoisResult{}, fmt.Errorf("invalid domain format")
	}
	TopLevelDomain := DomainParts[len(DomainParts)-1]

	WhoisServerHost, KnownServer := TldWhoisServers[TopLevelDomain]
	if !KnownServer {
		WhoisServerHost = "whois.iana.org"
	}

	RawRecord, QueryError := Service.QueryWhoisServer(WhoisServerHost, CleanDomain)
	if QueryError != nil {
		return model.WhoisResult{}, QueryError
	}

	ReferredServer := ExtractReferralServer(RawRecord)
	if ReferredServer != "" && ReferredServer != WhoisServerHost {
		ReferredRecord, ReferredError := Service.QueryWhoisServer(ReferredServer, CleanDomain)
		if ReferredError == nil && strings.TrimSpace(ReferredRecord) != "" {
			return model.WhoisResult{
				Domain:    CleanDomain,
				RawRecord: ReferredRecord,
				WhoisHost: ReferredServer,
			}, nil
		}
	}

	return model.WhoisResult{
		Domain:    CleanDomain,
		RawRecord: RawRecord,
		WhoisHost: WhoisServerHost,
	}, nil
}

func (Service *WhoisService) QueryWhoisServer(WhoisServerHost string, QueryDomain string) (string, error) {
	Connection, DialError := net.DialTimeout("tcp", net.JoinHostPort(WhoisServerHost, "43"), Service.Timeout)
	if DialError != nil {
		return "", DialError
	}
	defer Connection.Close()

	Connection.SetDeadline(time.Now().Add(Service.Timeout))
	_, WriteError := Connection.Write([]byte(QueryDomain + "\r\n"))
	if WriteError != nil {
		return "", WriteError
	}

	ResponseReader := bufio.NewReader(Connection)
	ResponseBytes, ReadError := io.ReadAll(ResponseReader)
	if ReadError != nil && len(ResponseBytes) == 0 {
		return "", ReadError
	}

	return string(ResponseBytes), nil
}

func ExtractReferralServer(RawRecord string) string {
	Lines := strings.Split(RawRecord, "\n")
	for _, Line := range Lines {
		LowerLine := strings.ToLower(Line)
		if strings.Contains(LowerLine, "whois server:") || strings.Contains(LowerLine, "refer:") {
			SplitLine := strings.SplitN(Line, ":", 2)
			if len(SplitLine) == 2 {
				return strings.TrimSpace(SplitLine[1])
			}
		}
	}
	return ""
}
