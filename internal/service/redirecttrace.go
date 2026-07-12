package service

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type RedirectTraceService struct {
	HttpClient *http.Client
}

func NewRedirectTraceService() *RedirectTraceService {
	return &RedirectTraceService{
		HttpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(Request *http.Request, Via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (Service *RedirectTraceService) TraceRedirects(TargetUrl string) (model.RedirectTraceResult, error) {
	CleanUrl := strings.TrimSpace(TargetUrl)
	if CleanUrl == "" {
		return model.RedirectTraceResult{}, fmt.Errorf("target url is required")
	}
	if !strings.HasPrefix(CleanUrl, "http://") && !strings.HasPrefix(CleanUrl, "https://") {
		CleanUrl = "https://" + CleanUrl
	}

	var Hops []model.RedirectHop
	CurrentUrl := CleanUrl
	const MaxHops = 15

	for HopIndex := 0; HopIndex < MaxHops; HopIndex++ {
		RequestInstance, RequestBuildError := http.NewRequest(http.MethodGet, CurrentUrl, nil)
		if RequestBuildError != nil {
			return model.RedirectTraceResult{}, RequestBuildError
		}
		RequestInstance.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Atmosphere-OSINT-Tool/1.0)")

		StartTime := time.Now()
		Response, RequestError := Service.HttpClient.Do(RequestInstance)
		if RequestError != nil {
			return model.RedirectTraceResult{}, RequestError
		}
		ElapsedMs := time.Since(StartTime).Milliseconds()
		Response.Body.Close()

		LocationHeader := Response.Header.Get("Location")
		Hops = append(Hops, model.RedirectHop{
			HopNumber:      HopIndex + 1,
			Url:            CurrentUrl,
			StatusCode:     Response.StatusCode,
			LocationHeader: LocationHeader,
			ResponseTimeMs: ElapsedMs,
		})

		if Response.StatusCode < 300 || Response.StatusCode >= 400 || LocationHeader == "" {
			break
		}

		CurrentUrl = ResolveRelativeUrl(CurrentUrl, LocationHeader)
	}

	FinalUrl := CleanUrl
	if len(Hops) > 0 {
		FinalUrl = Hops[len(Hops)-1].Url
	}

	return model.RedirectTraceResult{
		OriginalUrl: CleanUrl,
		FinalUrl:    FinalUrl,
		TotalHops:   len(Hops),
		Hops:        Hops,
	}, nil
}
