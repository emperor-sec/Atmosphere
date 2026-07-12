package service

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type PreviewService struct {
	HttpClient *http.Client
}

func NewPreviewService() *PreviewService {
	return &PreviewService{
		HttpClient: &http.Client{Timeout: 8 * time.Second},
	}
}

var MetaTagPatterns = map[string]*regexp.Regexp{
	"OgTitle":       regexp.MustCompile(`(?i)<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']*)["']`),
	"OgDescription": regexp.MustCompile(`(?i)<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']*)["']`),
	"OgImage":       regexp.MustCompile(`(?i)<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']*)["']`),
	"OgSiteName":    regexp.MustCompile(`(?i)<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']*)["']`),
	"Description":   regexp.MustCompile(`(?i)<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']`),
	"ThemeColor":    regexp.MustCompile(`(?i)<meta[^>]+name=["']theme-color["'][^>]+content=["']([^"']*)["']`),
}

var TitleTagPattern = regexp.MustCompile(`(?i)<title[^>]*>([^<]*)</title>`)
var FaviconPattern = regexp.MustCompile(`(?i)<link[^>]+rel=["'](?:shortcut icon|icon)["'][^>]+href=["']([^"']*)["']`)

func (Service *PreviewService) FetchPreview(TargetUrl string) (model.PreviewResult, error) {
	CleanUrl := strings.TrimSpace(TargetUrl)
	if CleanUrl == "" {
		return model.PreviewResult{}, fmt.Errorf("target url is required")
	}
	if !strings.HasPrefix(CleanUrl, "http://") && !strings.HasPrefix(CleanUrl, "https://") {
		CleanUrl = "https://" + CleanUrl
	}

	RequestInstance, RequestBuildError := http.NewRequest(http.MethodGet, CleanUrl, nil)
	if RequestBuildError != nil {
		return model.PreviewResult{}, RequestBuildError
	}
	RequestInstance.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Atmosphere-OSINT-Tool/1.0)")

	Response, RequestError := Service.HttpClient.Do(RequestInstance)
	if RequestError != nil {
		return model.PreviewResult{}, RequestError
	}
	defer Response.Body.Close()

	BodyBytes, ReadError := io.ReadAll(io.LimitReader(Response.Body, 256*1024))
	if ReadError != nil && len(BodyBytes) == 0 {
		return model.PreviewResult{}, ReadError
	}
	BodyText := string(BodyBytes)

	ExtractedFields := make(map[string]string)
	for FieldName, Pattern := range MetaTagPatterns {
		Matches := Pattern.FindStringSubmatch(BodyText)
		if len(Matches) > 1 {
			ExtractedFields[FieldName] = Matches[1]
		}
	}

	PageTitle := ""
	TitleMatches := TitleTagPattern.FindStringSubmatch(BodyText)
	if len(TitleMatches) > 1 {
		PageTitle = strings.TrimSpace(TitleMatches[1])
	}

	FaviconUrl := ""
	FaviconMatches := FaviconPattern.FindStringSubmatch(BodyText)
	if len(FaviconMatches) > 1 {
		FaviconUrl = ResolveRelativeUrl(CleanUrl, FaviconMatches[1])
	} else {
		FaviconUrl = ResolveRelativeUrl(CleanUrl, "/favicon.ico")
	}

	PreviewImageUrl := ExtractedFields["OgImage"]
	if PreviewImageUrl != "" {
		PreviewImageUrl = ResolveRelativeUrl(CleanUrl, PreviewImageUrl)
	}

	DescriptionText := ExtractedFields["OgDescription"]
	if DescriptionText == "" {
		DescriptionText = ExtractedFields["Description"]
	}

	return model.PreviewResult{
		Url:             CleanUrl,
		PageTitle:       PageTitle,
		OgTitle:         ExtractedFields["OgTitle"],
		OgSiteName:      ExtractedFields["OgSiteName"],
		Description:     DescriptionText,
		PreviewImageUrl: PreviewImageUrl,
		FaviconUrl:      FaviconUrl,
		ThemeColor:      ExtractedFields["ThemeColor"],
	}, nil
}

func ResolveRelativeUrl(BaseUrl string, TargetPath string) string {
	if strings.HasPrefix(TargetPath, "http://") || strings.HasPrefix(TargetPath, "https://") {
		return TargetPath
	}
	if strings.HasPrefix(TargetPath, "//") {
		return "https:" + TargetPath
	}

	SchemeSplit := strings.SplitN(BaseUrl, "://", 2)
	if len(SchemeSplit) != 2 {
		return TargetPath
	}
	SchemeName := SchemeSplit[0]
	HostAndPath := SchemeSplit[1]
	HostOnly := strings.SplitN(HostAndPath, "/", 2)[0]

	if strings.HasPrefix(TargetPath, "/") {
		return SchemeName + "://" + HostOnly + TargetPath
	}
	return SchemeName + "://" + HostOnly + "/" + TargetPath
}
