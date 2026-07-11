package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"atmosphere/internal/model"
	"atmosphere/internal/service"
)

type ApiHandler struct {
	GeoService           *service.GeoLocateService
	UserAgentService     *service.UserAgentService
	DnsService           *service.DnsResolveService
	SslCheckService      *service.SslCheckService
	WhoisService         *service.WhoisService
	HeaderInspectService *service.HeaderInspectService
}

func NewApiHandler(
	GeoService *service.GeoLocateService,
	UserAgentService *service.UserAgentService,
	DnsService *service.DnsResolveService,
	SslCheckService *service.SslCheckService,
	WhoisService *service.WhoisService,
	HeaderInspectService *service.HeaderInspectService,
) *ApiHandler {
	return &ApiHandler{
		GeoService:           GeoService,
		UserAgentService:     UserAgentService,
		DnsService:           DnsService,
		SslCheckService:      SslCheckService,
		WhoisService:         WhoisService,
		HeaderInspectService: HeaderInspectService,
	}
}

func (Handler *ApiHandler) HandleReport(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var ClientHintPayload model.ClientHint
	if Request.Body != nil {
		DecodeError := json.NewDecoder(Request.Body).Decode(&ClientHintPayload)
		if DecodeError != nil {
			ClientHintPayload = model.ClientHint{}
		}
	}

	ClientIp := service.ExtractClientIp(Request)
	RawUserAgent := Request.Header.Get("User-Agent")

	GeoResult, GeoError := Handler.GeoService.ResolvePublicIp(ClientIp)
	if GeoError != nil && GeoResult.Country == "" {
		GeoResult = model.GeoInfo{Ip: ClientIp, City: "Unresolved", Country: "Lookup Error"}
	}

	DeviceResult := Handler.UserAgentService.ParseUserAgent(RawUserAgent)

	NetworkResult := model.NetworkInfo{
		PublicIp:   ClientIp,
		LocalIps:   ClientHintPayload.LocalIps,
		Protocol:   Request.Proto,
		UserAgent:  RawUserAgent,
		AcceptLang: Request.Header.Get("Accept-Language"),
		Referer:    Request.Header.Get("Referer"),
		HostHeader: Request.Host,
	}

	Report := model.VisitorReport{
		RequestId:      GenerateRequestId(),
		Timestamp:      time.Now().UTC(),
		Geo:            GeoResult,
		Device:         DeviceResult,
		Network:        NetworkResult,
		Classification: service.ClassifyIpAddress(ClientIp),
		HttpHeaders:    service.ExtractHttpHeaders(Request),
	}

	WriteJsonSuccess(ResponseWriter, Report)
}

func (Handler *ApiHandler) HandleLookup(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var LookupPayload model.LookupRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&LookupPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	if LookupPayload.TargetIp == "" {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Target Ip Is Required")
		return
	}

	GeoResult, LookupError := Handler.GeoService.LookupArbitraryIp(LookupPayload.TargetIp)
	if LookupError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Or Unresolvable Ip Address")
		return
	}

	WriteJsonSuccess(ResponseWriter, GeoResult)
}

func (Handler *ApiHandler) HandleBatchLookup(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var BatchPayload model.BatchLookupRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&BatchPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	if len(BatchPayload.TargetIps) == 0 {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "At Least One Target Ip Is Required")
		return
	}

	if len(BatchPayload.TargetIps) > 20 {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Maximum 20 Ip Addresses Per Batch")
		return
	}

	BatchResult := Handler.GeoService.LookupBatchIps(BatchPayload.TargetIps)
	WriteJsonSuccess(ResponseWriter, BatchResult)
}

func (Handler *ApiHandler) HandleDnsResolve(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var DnsPayload model.DnsLookupRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&DnsPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	ResolveResult, ResolveError := Handler.DnsService.ResolveHostname(DnsPayload.TargetHost)
	if ResolveError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Hostname Could Not Be Resolved")
		return
	}

	WriteJsonSuccess(ResponseWriter, ResolveResult)
}

func (Handler *ApiHandler) HandleReverseDns(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var LookupPayload model.LookupRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&LookupPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	ReverseResult, ReverseError := Handler.DnsService.ReverseLookupIp(LookupPayload.TargetIp)
	if ReverseError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Reverse Dns Lookup Failed Or No Ptr Record Exists")
		return
	}

	WriteJsonSuccess(ResponseWriter, ReverseResult)
}

func (Handler *ApiHandler) HandlePortCheck(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var PortPayload model.PortCheckRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&PortPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	if PortPayload.TargetHost == "" {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Target Host Is Required")
		return
	}

	PortResult := Handler.DnsService.CheckPortsDetailed(PortPayload.TargetHost)
	WriteJsonSuccess(ResponseWriter, PortResult)
}

func (Handler *ApiHandler) HandleSslCheck(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var SslPayload model.SslCheckRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&SslPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	if SslPayload.TargetHost == "" {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Target Host Is Required")
		return
	}

	SslResult, SslError := Handler.SslCheckService.CheckCertificate(SslPayload.TargetHost)
	if SslError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Unable To Retrieve Certificate: "+SslError.Error())
		return
	}

	WriteJsonSuccess(ResponseWriter, SslResult)
}

func (Handler *ApiHandler) HandleWhoisLookup(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var WhoisPayload model.WhoisRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&WhoisPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	if WhoisPayload.TargetDomain == "" {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Target Domain Is Required")
		return
	}

	WhoisResult, WhoisError := Handler.WhoisService.LookupDomain(WhoisPayload.TargetDomain)
	if WhoisError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Whois Lookup Failed: "+WhoisError.Error())
		return
	}

	WriteJsonSuccess(ResponseWriter, WhoisResult)
}

func (Handler *ApiHandler) HandleHeaderInspect(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var HeaderPayload model.HeaderInspectRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&HeaderPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	if HeaderPayload.TargetUrl == "" {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Target Url Is Required")
		return
	}

	InspectResult, InspectError := Handler.HeaderInspectService.InspectUrl(HeaderPayload.TargetUrl)
	if InspectError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Header Inspection Failed: "+InspectError.Error())
		return
	}

	WriteJsonSuccess(ResponseWriter, InspectResult)
}

func (Handler *ApiHandler) HandleDnsRecords(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var RecordsPayload model.DnsRecordsRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&RecordsPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	if RecordsPayload.TargetHost == "" {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Target Host Is Required")
		return
	}

	RecordsResult, RecordsError := Handler.DnsService.LookupFullRecords(RecordsPayload.TargetHost)
	if RecordsError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Dns Records Lookup Failed: "+RecordsError.Error())
		return
	}

	WriteJsonSuccess(ResponseWriter, RecordsResult)
}

func (Handler *ApiHandler) HandlePing(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.Method != http.MethodPost {
		WriteJsonError(ResponseWriter, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	var PingPayload model.PingRequest
	if DecodeError := json.NewDecoder(Request.Body).Decode(&PingPayload); DecodeError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Invalid Request Body")
		return
	}

	if PingPayload.TargetHost == "" {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Target Host Is Required")
		return
	}

	PingResult, PingError := Handler.DnsService.RunPing(PingPayload.TargetHost)
	if PingError != nil {
		WriteJsonError(ResponseWriter, http.StatusBadRequest, "Ping Failed: "+PingError.Error())
		return
	}

	WriteJsonSuccess(ResponseWriter, PingResult)
}

func GenerateRequestId() string {
	RandomBytes := make([]byte, 8)
	_, ReadError := rand.Read(RandomBytes)
	if ReadError != nil {
		return "unknown-request-id"
	}
	return hex.EncodeToString(RandomBytes)
}

func WriteJsonSuccess(ResponseWriter http.ResponseWriter, Payload interface{}) {
	ResponseWriter.Header().Set("Content-Type", "application/json")
	ResponseWriter.WriteHeader(http.StatusOK)
	json.NewEncoder(ResponseWriter).Encode(Payload)
}

func WriteJsonError(ResponseWriter http.ResponseWriter, StatusCode int, Message string) {
	ResponseWriter.Header().Set("Content-Type", "application/json")
	ResponseWriter.WriteHeader(StatusCode)
	json.NewEncoder(ResponseWriter).Encode(map[string]string{"Error": Message})
}
