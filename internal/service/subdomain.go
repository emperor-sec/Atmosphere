package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type SubdomainService struct {
	HttpClient *http.Client
}

func NewSubdomainService() *SubdomainService {
	return &SubdomainService{
		HttpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

type CrtShEntry struct {
	NameValue string `json:"name_value"`
}

func (Service *SubdomainService) EnumerateSubdomains(TargetDomain string) (model.SubdomainResult, error) {
	CleanDomain := strings.ToLower(strings.TrimSpace(TargetDomain))
	CleanDomain = strings.TrimPrefix(CleanDomain, "https://")
	CleanDomain = strings.TrimPrefix(CleanDomain, "http://")
	CleanDomain = strings.TrimSuffix(CleanDomain, "/")
	if CleanDomain == "" {
		return model.SubdomainResult{}, fmt.Errorf("target domain is required")
	}

	RequestUrl := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", CleanDomain)

	RequestInstance, RequestBuildError := http.NewRequest(http.MethodGet, RequestUrl, nil)
	if RequestBuildError != nil {
		return model.SubdomainResult{}, RequestBuildError
	}
	RequestInstance.Header.Set("User-Agent", "Atmosphere-OSINT-Tool")

	Response, RequestError := Service.HttpClient.Do(RequestInstance)
	if RequestError != nil {
		return model.SubdomainResult{}, RequestError
	}
	defer Response.Body.Close()

	if Response.StatusCode != http.StatusOK {
		return model.SubdomainResult{}, fmt.Errorf("certificate transparency lookup failed with status %d", Response.StatusCode)
	}

	var Entries []CrtShEntry
	if DecodeError := json.NewDecoder(Response.Body).Decode(&Entries); DecodeError != nil {
		return model.SubdomainResult{}, fmt.Errorf("failed to parse certificate transparency response")
	}

	UniqueSubdomains := make(map[string]bool)
	for _, Entry := range Entries {
		NameLines := strings.Split(Entry.NameValue, "\n")
		for _, NameLine := range NameLines {
			TrimmedName := strings.ToLower(strings.TrimSpace(NameLine))
			if TrimmedName == "" || strings.Contains(TrimmedName, "*") {
				continue
			}
			if strings.HasSuffix(TrimmedName, "."+CleanDomain) || TrimmedName == CleanDomain {
				UniqueSubdomains[TrimmedName] = true
			}
		}
	}

	var SortedSubdomains []string
	for SubdomainName := range UniqueSubdomains {
		SortedSubdomains = append(SortedSubdomains, SubdomainName)
	}
	sort.Strings(SortedSubdomains)

	return model.SubdomainResult{
		Domain:         CleanDomain,
		Subdomains:     SortedSubdomains,
		TotalDiscovered: len(SortedSubdomains),
	}, nil
}
