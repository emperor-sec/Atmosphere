package service

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type HeaderInspectService struct {
	HttpClient *http.Client
}

func NewHeaderInspectService() *HeaderInspectService {
	return &HeaderInspectService{
		HttpClient: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(Request *http.Request, Via []*http.Request) error {
				if len(Via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (Service *HeaderInspectService) InspectUrl(TargetUrl string) (model.HeaderInspectResult, error) {
	CleanUrl := strings.TrimSpace(TargetUrl)
	if CleanUrl == "" {
		return model.HeaderInspectResult{}, fmt.Errorf("target url is required")
	}
	if !strings.HasPrefix(CleanUrl, "http://") && !strings.HasPrefix(CleanUrl, "https://") {
		CleanUrl = "https://" + CleanUrl
	}

	RequestInstance, RequestBuildError := http.NewRequest(http.MethodGet, CleanUrl, nil)
	if RequestBuildError != nil {
		return model.HeaderInspectResult{}, RequestBuildError
	}
	RequestInstance.Header.Set("User-Agent", "Atmosphere-OSINT-Tool")

	StartTime := time.Now()
	Response, RequestError := Service.HttpClient.Do(RequestInstance)
	if RequestError != nil {
		return model.HeaderInspectResult{}, RequestError
	}
	defer Response.Body.Close()
	ElapsedMs := time.Since(StartTime).Milliseconds()

	var HeaderEntries []model.HttpHeaderEntry
	for HeaderName, HeaderValues := range Response.Header {
		HeaderEntries = append(HeaderEntries, model.HttpHeaderEntry{
			Name:  HeaderName,
			Value: strings.Join(HeaderValues, ", "),
		})
	}

	SecurityFlags := model.SecurityHeaderFlags{
		HasHsts:             Response.Header.Get("Strict-Transport-Security") != "",
		HasCsp:              Response.Header.Get("Content-Security-Policy") != "",
		HasXFrameOptions:    Response.Header.Get("X-Frame-Options") != "",
		HasXContentTypeOpts: Response.Header.Get("X-Content-Type-Options") != "",
		HasReferrerPolicy:   Response.Header.Get("Referrer-Policy") != "",
	}

	FinalUrl := CleanUrl
	if Response.Request != nil && Response.Request.URL != nil {
		FinalUrl = Response.Request.URL.String()
	}

	return model.HeaderInspectResult{
		Url:            CleanUrl,
		StatusCode:     Response.StatusCode,
		StatusText:     Response.Status,
		FinalUrl:       FinalUrl,
		Headers:        HeaderEntries,
		ResponseTimeMs: ElapsedMs,
		SecurityFlags:  SecurityFlags,
	}, nil
}
