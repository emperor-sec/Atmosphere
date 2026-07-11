package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type GeoLocateService struct {
	HttpClient *http.Client
}

type IpApiComResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	Isp         string  `json:"isp"`
	Org         string  `json:"org"`
	As          string  `json:"as"`
	Continent   string  `json:"continent"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
	Query       string  `json:"query"`
}

type IpwhoisResponse struct {
	Success       bool    `json:"success"`
	Ip            string  `json:"ip"`
	City          string  `json:"city"`
	Region        string  `json:"region"`
	Country       string  `json:"country"`
	CountryCode   string  `json:"country_code"`
	ContinentName string  `json:"continent"`
	Postal        string  `json:"postal"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Timezone      struct {
		Id string `json:"id"`
	} `json:"timezone"`
	Connection struct {
		Isp string `json:"isp"`
		Org string `json:"org"`
		Asn string `json:"asn"`
	} `json:"connection"`
}

type IpapiCoResponse struct {
	Ip          string  `json:"ip"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	CountryName string  `json:"country_name"`
	CountryCode string  `json:"country_code"`
	Continent   string  `json:"continent_code"`
	Postal      string  `json:"postal"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
	Org         string  `json:"org"`
	Asn         string  `json:"asn"`
	Error       bool    `json:"error"`
}

func NewGeoLocateService() *GeoLocateService {
	return &GeoLocateService{
		HttpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (Service *GeoLocateService) ResolvePublicIp(ClientIp string) (model.GeoInfo, error) {
	if IsPrivateIp(ClientIp) || IsLoopbackIp(ClientIp) {
		DiscoveredIp, DiscoveryError := Service.DiscoverActualPublicIp()
		if DiscoveryError != nil || DiscoveredIp == "" || IsPrivateIp(DiscoveredIp) || IsLoopbackIp(DiscoveredIp) {
			return model.GeoInfo{
				Ip:          ClientIp,
				City:        "Unresolved",
				Region:      "Unresolved",
				Country:     "Private Network Range",
				Asn:         "N/A",
				SourceLabel: "Local Network Detection",
			}, nil
		}
		return Service.ResolvePublicIp(DiscoveredIp)
	}

	ProviderChain := []func(string) (model.GeoInfo, error){
		Service.QueryIpApiCom,
		Service.QueryIpwhoisApp,
		Service.QueryIpapiCo,
	}

	var LastError error
	for _, ProviderFunc := range ProviderChain {
		GeoResult, ProviderError := ProviderFunc(ClientIp)
		if ProviderError == nil && GeoResult.Country != "" {
			return GeoResult, nil
		}
		LastError = ProviderError
	}

	return model.GeoInfo{
		Ip:          ClientIp,
		City:        "Unknown",
		Country:     "All Providers Unavailable",
		Asn:         "N/A",
		SourceLabel: "None",
	}, LastError
}

func (Service *GeoLocateService) DiscoverActualPublicIp() (string, error) {
	DiscoveryEndpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	for _, EndpointUrl := range DiscoveryEndpoints {
		Response, RequestError := Service.HttpClient.Get(EndpointUrl)
		if RequestError != nil {
			continue
		}
		BodyBytes, ReadError := io.ReadAll(io.LimitReader(Response.Body, 128))
		Response.Body.Close()
		if ReadError != nil {
			continue
		}
		CandidateIp := strings.TrimSpace(string(BodyBytes))
		if net.ParseIP(CandidateIp) != nil {
			return CandidateIp, nil
		}
	}

	return "", fmt.Errorf("unable to discover public ip from any endpoint")
}

func (Service *GeoLocateService) QueryIpApiCom(ClientIp string) (model.GeoInfo, error) {
	RequestUrl := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,continent,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query",
		ClientIp,
	)

	Response, RequestError := Service.HttpClient.Get(RequestUrl)
	if RequestError != nil {
		return model.GeoInfo{}, RequestError
	}
	defer Response.Body.Close()

	var ApiResult IpApiComResponse
	if DecodeError := json.NewDecoder(Response.Body).Decode(&ApiResult); DecodeError != nil {
		return model.GeoInfo{}, DecodeError
	}

	if ApiResult.Status != "success" {
		return model.GeoInfo{}, fmt.Errorf("ip-api.com lookup failed")
	}

	Result := Service.BuildGeoInfo(
		ApiResult.Query, ApiResult.City, ApiResult.RegionName, ApiResult.Country, ApiResult.CountryCode,
		ApiResult.Continent, ApiResult.Zip, ApiResult.Lat, ApiResult.Lon, ApiResult.Timezone,
		ApiResult.Isp, ApiResult.Org, ApiResult.As,
	)
	Result.Mobile = ApiResult.Mobile
	Result.Proxy = ApiResult.Proxy
	Result.Hosting = ApiResult.Hosting
	Result.SourceLabel = "ip-api.com"
	return Result, nil
}

func (Service *GeoLocateService) QueryIpwhoisApp(ClientIp string) (model.GeoInfo, error) {
	RequestUrl := fmt.Sprintf("https://ipwho.is/%s", ClientIp)

	Response, RequestError := Service.HttpClient.Get(RequestUrl)
	if RequestError != nil {
		return model.GeoInfo{}, RequestError
	}
	defer Response.Body.Close()

	var ApiResult IpwhoisResponse
	if DecodeError := json.NewDecoder(Response.Body).Decode(&ApiResult); DecodeError != nil {
		return model.GeoInfo{}, DecodeError
	}

	if !ApiResult.Success {
		return model.GeoInfo{}, fmt.Errorf("ipwho.is lookup failed")
	}

	Result := Service.BuildGeoInfo(
		ApiResult.Ip, ApiResult.City, ApiResult.Region, ApiResult.Country, ApiResult.CountryCode,
		ApiResult.ContinentName, ApiResult.Postal, ApiResult.Latitude, ApiResult.Longitude, ApiResult.Timezone.Id,
		ApiResult.Connection.Isp, ApiResult.Connection.Org, ApiResult.Connection.Asn,
	)
	Result.SourceLabel = "ipwho.is"
	return Result, nil
}

func (Service *GeoLocateService) QueryIpapiCo(ClientIp string) (model.GeoInfo, error) {
	RequestUrl := fmt.Sprintf("https://ipapi.co/%s/json/", ClientIp)

	Request, RequestBuildError := http.NewRequest(http.MethodGet, RequestUrl, nil)
	if RequestBuildError != nil {
		return model.GeoInfo{}, RequestBuildError
	}
	Request.Header.Set("User-Agent", "Atmosphere-OSINT-Tool")

	Response, RequestError := Service.HttpClient.Do(Request)
	if RequestError != nil {
		return model.GeoInfo{}, RequestError
	}
	defer Response.Body.Close()

	var ApiResult IpapiCoResponse
	if DecodeError := json.NewDecoder(Response.Body).Decode(&ApiResult); DecodeError != nil {
		return model.GeoInfo{}, DecodeError
	}

	if ApiResult.Error || ApiResult.CountryName == "" {
		return model.GeoInfo{}, fmt.Errorf("ipapi.co lookup failed")
	}

	Result := Service.BuildGeoInfo(
		ApiResult.Ip, ApiResult.City, ApiResult.Region, ApiResult.CountryName, ApiResult.CountryCode,
		ApiResult.Continent, ApiResult.Postal, ApiResult.Latitude, ApiResult.Longitude, ApiResult.Timezone,
		"Unknown", ApiResult.Org, ApiResult.Asn,
	)
	Result.SourceLabel = "ipapi.co"
	return Result, nil
}

func (Service *GeoLocateService) BuildGeoInfo(
	Ip, City, Region, Country, CountryCode, Continent, PostalCode string,
	Latitude, Longitude float64, Timezone, Isp, Org, Asn string,
) model.GeoInfo {
	GoogleMapUrl := fmt.Sprintf("https://www.google.com/maps?q=%s,%s", FormatCoordinate(Latitude), FormatCoordinate(Longitude))
	OsmMapUrl := fmt.Sprintf(
		"https://www.openstreetmap.org/?mlat=%s&mlon=%s#map=12/%s/%s",
		FormatCoordinate(Latitude), FormatCoordinate(Longitude), FormatCoordinate(Latitude), FormatCoordinate(Longitude),
	)

	CurrencyCode, CallingCode := ResolveCountryMeta(CountryCode)

	return model.GeoInfo{
		Ip:           Ip,
		City:         City,
		Region:       Region,
		Country:      Country,
		CountryCode:  CountryCode,
		Continent:    Continent,
		PostalCode:   PostalCode,
		Latitude:     Latitude,
		Longitude:    Longitude,
		Altitude:     "Not Available From IP Geolocation",
		Timezone:     Timezone,
		CurrencyCode: CurrencyCode,
		CallingCode:  CallingCode,
		Isp:          Isp,
		Org:          Org,
		Asn:          Asn,
		GoogleMapUrl: GoogleMapUrl,
		OsmMapUrl:    OsmMapUrl,
	}
}

var CountryMetaTable = map[string][2]string{
	"US": {"USD", "+1"}, "GB": {"GBP", "+44"}, "ID": {"IDR", "+62"}, "SG": {"SGD", "+65"},
	"MY": {"MYR", "+60"}, "JP": {"JPY", "+81"}, "KR": {"KRW", "+82"}, "CN": {"CNY", "+86"},
	"IN": {"INR", "+91"}, "AU": {"AUD", "+61"}, "DE": {"EUR", "+49"}, "FR": {"EUR", "+33"},
	"NL": {"EUR", "+31"}, "CA": {"CAD", "+1"}, "BR": {"BRL", "+55"}, "RU": {"RUB", "+7"},
	"AE": {"AED", "+971"}, "SA": {"SAR", "+966"}, "TH": {"THB", "+66"}, "VN": {"VND", "+84"},
	"PH": {"PHP", "+63"},
}

func ResolveCountryMeta(CountryCode string) (string, string) {
	if MetaEntry, Found := CountryMetaTable[CountryCode]; Found {
		return MetaEntry[0], MetaEntry[1]
	}
	return "Unknown", "Unknown"
}

func FormatCoordinate(Value float64) string {
	return fmt.Sprintf("%.6f", Value)
}

func ClassifyIpAddress(IpAddress string) model.IpClassification {
	ParsedIp := net.ParseIP(IpAddress)
	if ParsedIp == nil {
		return model.IpClassification{IpVersion: "Invalid"}
	}

	IpVersion := "IPv6"
	if ParsedIp.To4() != nil {
		IpVersion = "IPv4"
	}

	return model.IpClassification{
		IpVersion:    IpVersion,
		IsPrivate:    IsPrivateIp(IpAddress),
		IsLoopback:   ParsedIp.IsLoopback(),
		IsMulticast:  ParsedIp.IsMulticast(),
		BinaryOctets: BuildBinaryRepresentation(ParsedIp),
	}
}

func BuildBinaryRepresentation(ParsedIp net.IP) string {
	Ipv4Form := ParsedIp.To4()
	if Ipv4Form == nil {
		return "Not Applicable For IPv6"
	}

	var BinarySegments []string
	for _, Octet := range Ipv4Form {
		BinarySegments = append(BinarySegments, fmt.Sprintf("%08b", Octet))
	}
	return strings.Join(BinarySegments, ".")
}

func ExtractHttpHeaders(Request *http.Request) []model.HttpHeaderEntry {
	var HeaderEntries []model.HttpHeaderEntry
	RelevantHeaders := []string{
		"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
		"Referer", "Sec-Ch-Ua", "Sec-Ch-Ua-Platform", "Sec-Fetch-Site",
		"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Connection", "Cache-Control", "Dnt",
	}

	for _, HeaderName := range RelevantHeaders {
		HeaderValue := Request.Header.Get(HeaderName)
		if HeaderValue != "" {
			HeaderEntries = append(HeaderEntries, model.HttpHeaderEntry{Name: HeaderName, Value: HeaderValue})
		}
	}

	return HeaderEntries
}

func (Service *GeoLocateService) LookupArbitraryIp(TargetIp string) (model.GeoInfo, error) {
	ParsedIp := net.ParseIP(strings.TrimSpace(TargetIp))
	if ParsedIp == nil {
		return model.GeoInfo{}, fmt.Errorf("invalid ip address format")
	}
	return Service.ResolvePublicIp(ParsedIp.String())
}

func (Service *GeoLocateService) LookupBatchIps(TargetIps []string) model.BatchLookupResult {
	var Results []model.GeoInfo
	var Failed []string

	for _, RawIp := range TargetIps {
		TrimmedIp := strings.TrimSpace(RawIp)
		if TrimmedIp == "" {
			continue
		}
		GeoResult, LookupError := Service.LookupArbitraryIp(TrimmedIp)
		if LookupError != nil {
			Failed = append(Failed, TrimmedIp)
			continue
		}
		Results = append(Results, GeoResult)
	}

	return model.BatchLookupResult{Results: Results, Failed: Failed}
}

func ExtractClientIp(Request *http.Request) string {
	ForwardedFor := Request.Header.Get("X-Forwarded-For")
	if ForwardedFor != "" {
		Parts := strings.Split(ForwardedFor, ",")
		return strings.TrimSpace(Parts[0])
	}

	RealIp := Request.Header.Get("X-Real-Ip")
	if RealIp != "" {
		return strings.TrimSpace(RealIp)
	}

	HostPart, _, SplitError := net.SplitHostPort(Request.RemoteAddr)
	if SplitError != nil {
		return Request.RemoteAddr
	}
	return HostPart
}

func IsPrivateIp(IpAddress string) bool {
	ParsedIp := net.ParseIP(IpAddress)
	if ParsedIp == nil {
		return false
	}

	PrivateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fc00::/7",
	}

	for _, Range := range PrivateRanges {
		_, SubNet, ParseError := net.ParseCIDR(Range)
		if ParseError != nil {
			continue
		}
		if SubNet.Contains(ParsedIp) {
			return true
		}
	}
	return false
}

func IsLoopbackIp(IpAddress string) bool {
	ParsedIp := net.ParseIP(IpAddress)
	if ParsedIp == nil {
		return false
	}
	return ParsedIp.IsLoopback()
}

func GetLocalNetworkIps() []string {
	var LocalAddresses []string

	Interfaces, InterfaceError := net.Interfaces()
	if InterfaceError != nil {
		return LocalAddresses
	}

	for _, Interface := range Interfaces {
		Addresses, AddressError := Interface.Addrs()
		if AddressError != nil {
			continue
		}
		for _, Address := range Addresses {
			var IpNet *net.IPNet
			switch TypedAddress := Address.(type) {
			case *net.IPNet:
				IpNet = TypedAddress
			}
			if IpNet == nil || IpNet.IP.IsLoopback() {
				continue
			}
			if IpNet.IP.To4() != nil {
				LocalAddresses = append(LocalAddresses, IpNet.IP.String())
			}
		}
	}
	return LocalAddresses
}
