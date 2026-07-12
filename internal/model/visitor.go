package model

import "time"

type GeoInfo struct {
	Ip           string  `json:"Ip"`
	City         string  `json:"City"`
	Region       string  `json:"Region"`
	Country      string  `json:"Country"`
	CountryCode  string  `json:"CountryCode"`
	Continent    string  `json:"Continent"`
	PostalCode   string  `json:"PostalCode"`
	Latitude     float64 `json:"Latitude"`
	Longitude    float64 `json:"Longitude"`
	Altitude     string  `json:"Altitude"`
	Timezone     string  `json:"Timezone"`
	UtcOffset    string  `json:"UtcOffset"`
	CurrencyCode string  `json:"CurrencyCode"`
	CallingCode  string  `json:"CallingCode"`
	Isp          string  `json:"Isp"`
	Org          string  `json:"Org"`
	Asn          string  `json:"Asn"`
	Mobile       bool    `json:"Mobile"`
	Proxy        bool    `json:"Proxy"`
	Hosting      bool    `json:"Hosting"`
	GoogleMapUrl string  `json:"GoogleMapUrl"`
	OsmMapUrl    string  `json:"OsmMapUrl"`
	SourceLabel  string  `json:"SourceLabel"`
}

type IpClassification struct {
	IpVersion    string `json:"IpVersion"`
	IsPrivate    bool   `json:"IsPrivate"`
	IsLoopback   bool   `json:"IsLoopback"`
	IsMulticast  bool   `json:"IsMulticast"`
	BinaryOctets string `json:"BinaryOctets"`
}

type HttpHeaderEntry struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}

type DeviceInfo struct {
	BrowserName    string `json:"BrowserName"`
	BrowserVersion string `json:"BrowserVersion"`
	OsName         string `json:"OsName"`
	OsVersion      string `json:"OsVersion"`
	DeviceType     string `json:"DeviceType"`
	DeviceVendor   string `json:"DeviceVendor"`
	DeviceModel    string `json:"DeviceModel"`
	EngineName     string `json:"EngineName"`
	EngineVersion  string `json:"EngineVersion"`
	IsMobile       bool   `json:"IsMobile"`
	IsTablet       bool   `json:"IsTablet"`
	IsDesktop      bool   `json:"IsDesktop"`
	IsBot          bool   `json:"IsBot"`
}

type NetworkInfo struct {
	PublicIp   string   `json:"PublicIp"`
	LocalIps   []string `json:"LocalIps"`
	Protocol   string   `json:"Protocol"`
	UserAgent  string   `json:"UserAgent"`
	AcceptLang string   `json:"AcceptLang"`
	Referer    string   `json:"Referer"`
	HostHeader string   `json:"HostHeader"`
}

type VisitorReport struct {
	RequestId      string            `json:"RequestId"`
	Timestamp      time.Time         `json:"Timestamp"`
	Geo            GeoInfo           `json:"Geo"`
	Device         DeviceInfo        `json:"Device"`
	Network        NetworkInfo       `json:"Network"`
	Classification IpClassification  `json:"Classification"`
	HttpHeaders    []HttpHeaderEntry `json:"HttpHeaders"`
}

type ClientHint struct {
	LocalIps        []string `json:"LocalIps"`
	ScreenWidth     int      `json:"ScreenWidth"`
	ScreenHeight    int      `json:"ScreenHeight"`
	ColorDepth      int      `json:"ColorDepth"`
	PixelRatio      float64  `json:"PixelRatio"`
	HardwareThreads int      `json:"HardwareThreads"`
	DeviceMemory    float64  `json:"DeviceMemory"`
	TimezoneName    string   `json:"TimezoneName"`
	LanguageList    []string `json:"LanguageList"`
	PlatformName    string   `json:"PlatformName"`
	TouchSupport    bool     `json:"TouchSupport"`
	CookieEnabled   bool     `json:"CookieEnabled"`
	DoNotTrack      string   `json:"DoNotTrack"`
	ConnectionType  string   `json:"ConnectionType"`
}

type LookupRequest struct {
	TargetIp string `json:"TargetIp"`
}

type BatchLookupRequest struct {
	TargetIps []string `json:"TargetIps"`
}

type BatchLookupResult struct {
	Results []GeoInfo `json:"Results"`
	Failed  []string  `json:"Failed"`
}

type DnsLookupRequest struct {
	TargetHost string `json:"TargetHost"`
}

type DnsLookupResult struct {
	Hostname    string   `json:"Hostname"`
	ResolvedIps []string `json:"ResolvedIps"`
}

type ReverseDnsResult struct {
	Ip        string   `json:"Ip"`
	Hostnames []string `json:"Hostnames"`
}

type SslCheckRequest struct {
	TargetHost string `json:"TargetHost"`
}

type SslCertificateInfo struct {
	Subject            string   `json:"Subject"`
	Issuer             string   `json:"Issuer"`
	SerialNumber       string   `json:"SerialNumber"`
	SignatureAlgorithm string   `json:"SignatureAlgorithm"`
	NotBefore          string   `json:"NotBefore"`
	NotAfter           string   `json:"NotAfter"`
	DaysUntilExpiry    int      `json:"DaysUntilExpiry"`
	IsExpired          bool     `json:"IsExpired"`
	IsSelfSigned       bool     `json:"IsSelfSigned"`
	DnsNames           []string `json:"DnsNames"`
	TlsVersion         string   `json:"TlsVersion"`
	CipherSuite        string   `json:"CipherSuite"`
}

type SslCheckResult struct {
	Hostname    string                `json:"Hostname"`
	Certificate SslCertificateInfo    `json:"Certificate"`
	ChainLength int                   `json:"ChainLength"`
	ChainInfo   []SslCertificateInfo  `json:"ChainInfo"`
}

type WhoisRequest struct {
	TargetDomain string `json:"TargetDomain"`
}

type WhoisResult struct {
	Domain    string `json:"Domain"`
	RawRecord string `json:"RawRecord"`
	WhoisHost string `json:"WhoisHost"`
}

type HeaderInspectRequest struct {
	TargetUrl string `json:"TargetUrl"`
}

type HeaderInspectResult struct {
	Url            string            `json:"Url"`
	StatusCode     int               `json:"StatusCode"`
	StatusText     string            `json:"StatusText"`
	FinalUrl       string            `json:"FinalUrl"`
	Headers        []HttpHeaderEntry `json:"Headers"`
	ResponseTimeMs int64             `json:"ResponseTimeMs"`
	SecurityFlags  SecurityHeaderFlags `json:"SecurityFlags"`
}

type SecurityHeaderFlags struct {
	HasHsts             bool `json:"HasHsts"`
	HasCsp              bool `json:"HasCsp"`
	HasXFrameOptions    bool `json:"HasXFrameOptions"`
	HasXContentTypeOpts bool `json:"HasXContentTypeOpts"`
	HasReferrerPolicy   bool `json:"HasReferrerPolicy"`
}

type DnsRecordsRequest struct {
	TargetHost string `json:"TargetHost"`
}

type DnsRecordsResult struct {
	Hostname   string   `json:"Hostname"`
	ARecords   []string `json:"ARecords"`
	AaaaRecords []string `json:"AaaaRecords"`
	MxRecords  []string `json:"MxRecords"`
	TxtRecords []string `json:"TxtRecords"`
	NsRecords  []string `json:"NsRecords"`
	CnameRecord string  `json:"CnameRecord"`
}

type PortCheckRequest struct {
	TargetHost string `json:"TargetHost"`
}

type PortCheckEntry struct {
	ServiceName string `json:"ServiceName"`
	Port        int    `json:"Port"`
	IsOpen      bool   `json:"IsOpen"`
	LatencyMs   int64  `json:"LatencyMs"`
}

type PortCheckResult struct {
	Hostname string           `json:"Hostname"`
	Ports    []PortCheckEntry `json:"Ports"`
}

type PingRequest struct {
	TargetHost string `json:"TargetHost"`
}

type PingAttempt struct {
	Sequence  int   `json:"Sequence"`
	Success   bool  `json:"Success"`
	LatencyMs int64 `json:"LatencyMs"`
}

type PingResult struct {
	Hostname     string        `json:"Hostname"`
	ResolvedIp   string        `json:"ResolvedIp"`
	Attempts     []PingAttempt `json:"Attempts"`
	MinLatencyMs int64         `json:"MinLatencyMs"`
	MaxLatencyMs int64         `json:"MaxLatencyMs"`
	AvgLatencyMs int64         `json:"AvgLatencyMs"`
	PacketLoss   float64       `json:"PacketLoss"`
}

type TechDetectRequest struct {
	TargetUrl string `json:"TargetUrl"`
}

type TechDetectEntry struct {
	Name     string `json:"Name"`
	Category string `json:"Category"`
}

type TechDetectResult struct {
	Url             string            `json:"Url"`
	DetectedEntries []TechDetectEntry `json:"DetectedEntries"`
	ServerHeader    string            `json:"ServerHeader"`
	PoweredByHeader string            `json:"PoweredByHeader"`
}

type BlacklistRequest struct {
	TargetIp string `json:"TargetIp"`
}

type BlacklistEntry struct {
	ZoneName string `json:"ZoneName"`
	IsListed bool   `json:"IsListed"`
}

type BlacklistResult struct {
	Ip           string           `json:"Ip"`
	Entries      []BlacklistEntry `json:"Entries"`
	ListedCount  int              `json:"ListedCount"`
	TotalChecked int              `json:"TotalChecked"`
}

type PreviewRequest struct {
	TargetUrl string `json:"TargetUrl"`
}

type PreviewResult struct {
	Url             string `json:"Url"`
	PageTitle       string `json:"PageTitle"`
	OgTitle         string `json:"OgTitle"`
	OgSiteName      string `json:"OgSiteName"`
	Description     string `json:"Description"`
	PreviewImageUrl string `json:"PreviewImageUrl"`
	FaviconUrl      string `json:"FaviconUrl"`
	ThemeColor      string `json:"ThemeColor"`
}

type SubdomainRequest struct {
	TargetDomain string `json:"TargetDomain"`
}

type SubdomainResult struct {
	Domain          string   `json:"Domain"`
	Subdomains      []string `json:"Subdomains"`
	TotalDiscovered int      `json:"TotalDiscovered"`
}

type FaviconRequest struct {
	TargetUrl string `json:"TargetUrl"`
}

type FaviconResult struct {
	Url            string `json:"Url"`
	FaviconUrl     string `json:"FaviconUrl"`
	Md5Hash        string `json:"Md5Hash"`
	Mmh3Hash       int32  `json:"Mmh3Hash"`
	SizeBytes      int    `json:"SizeBytes"`
	ShodanQueryUrl string `json:"ShodanQueryUrl"`
}

type RedirectTraceRequest struct {
	TargetUrl string `json:"TargetUrl"`
}

type RedirectHop struct {
	HopNumber      int    `json:"HopNumber"`
	Url            string `json:"Url"`
	StatusCode     int    `json:"StatusCode"`
	LocationHeader string `json:"LocationHeader"`
	ResponseTimeMs int64  `json:"ResponseTimeMs"`
}

type RedirectTraceResult struct {
	OriginalUrl string        `json:"OriginalUrl"`
	FinalUrl    string        `json:"FinalUrl"`
	TotalHops   int           `json:"TotalHops"`
	Hops        []RedirectHop `json:"Hops"`
}
