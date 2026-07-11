package service

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type SslCheckService struct {
	Timeout time.Duration
}

func NewSslCheckService() *SslCheckService {
	return &SslCheckService{Timeout: 6 * time.Second}
}

func (Service *SslCheckService) CheckCertificate(TargetHost string) (model.SslCheckResult, error) {
	CleanHost := strings.TrimSpace(TargetHost)
	CleanHost = strings.TrimPrefix(CleanHost, "https://")
	CleanHost = strings.TrimPrefix(CleanHost, "http://")
	CleanHost = strings.TrimSuffix(CleanHost, "/")
	if CleanHost == "" {
		return model.SslCheckResult{}, fmt.Errorf("target host is required")
	}

	HostOnly := CleanHost
	if strings.Contains(CleanHost, "/") {
		HostOnly = strings.SplitN(CleanHost, "/", 2)[0]
	}

	Address := HostOnly
	if !strings.Contains(HostOnly, ":") {
		Address = net.JoinHostPort(HostOnly, "443")
	}

	DialerInstance := &net.Dialer{Timeout: Service.Timeout}
	TlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: strings.Split(HostOnly, ":")[0]}

	Connection, DialError := tls.DialWithDialer(DialerInstance, "tcp", Address, TlsConfig)
	if DialError != nil {
		return model.SslCheckResult{}, DialError
	}
	defer Connection.Close()

	ConnectionState := Connection.ConnectionState()
	if len(ConnectionState.PeerCertificates) == 0 {
		return model.SslCheckResult{}, fmt.Errorf("no certificate presented by host")
	}

	LeafCertificate := ConnectionState.PeerCertificates[0]
	CertificateInfo := Service.BuildCertificateInfo(LeafCertificate, &ConnectionState)

	var ChainInfo []model.SslCertificateInfo
	for _, ChainCertificate := range ConnectionState.PeerCertificates {
		ChainInfo = append(ChainInfo, Service.BuildCertificateInfo(ChainCertificate, nil))
	}

	return model.SslCheckResult{
		Hostname:    HostOnly,
		Certificate: CertificateInfo,
		ChainLength: len(ConnectionState.PeerCertificates),
		ChainInfo:   ChainInfo,
	}, nil
}

func (Service *SslCheckService) BuildCertificateInfo(Certificate *x509.Certificate, ConnectionState *tls.ConnectionState) model.SslCertificateInfo {
	DaysRemaining := int(time.Until(Certificate.NotAfter).Hours() / 24)

	Info := model.SslCertificateInfo{
		Subject:            Certificate.Subject.CommonName,
		Issuer:             Certificate.Issuer.CommonName,
		SerialNumber:       Certificate.SerialNumber.String(),
		SignatureAlgorithm: Certificate.SignatureAlgorithm.String(),
		NotBefore:          Certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           Certificate.NotAfter.UTC().Format(time.RFC3339),
		DaysUntilExpiry:    DaysRemaining,
		IsExpired:          time.Now().After(Certificate.NotAfter),
		IsSelfSigned:       Certificate.Subject.CommonName == Certificate.Issuer.CommonName,
		DnsNames:           Certificate.DNSNames,
	}

	if ConnectionState != nil {
		Info.TlsVersion = ResolveTlsVersionName(ConnectionState.Version)
		Info.CipherSuite = tls.CipherSuiteName(ConnectionState.CipherSuite)
	}

	return Info
}

func ResolveTlsVersionName(VersionCode uint16) string {
	switch VersionCode {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
