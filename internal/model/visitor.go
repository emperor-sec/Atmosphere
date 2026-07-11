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
