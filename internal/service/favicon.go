package service

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"atmosphere/internal/model"
)

type FaviconService struct {
	HttpClient *http.Client
}

func NewFaviconService() *FaviconService {
	return &FaviconService{
		HttpClient: &http.Client{Timeout: 8 * time.Second},
	}
}

func (Service *FaviconService) LookupFaviconHash(TargetUrl string) (model.FaviconResult, error) {
	CleanUrl := strings.TrimSpace(TargetUrl)
	if CleanUrl == "" {
		return model.FaviconResult{}, fmt.Errorf("target url is required")
	}
	if !strings.HasPrefix(CleanUrl, "http://") && !strings.HasPrefix(CleanUrl, "https://") {
		CleanUrl = "https://" + CleanUrl
	}

	FaviconUrl := ResolveRelativeUrl(CleanUrl, "/favicon.ico")

	RequestInstance, RequestBuildError := http.NewRequest(http.MethodGet, FaviconUrl, nil)
	if RequestBuildError != nil {
		return model.FaviconResult{}, RequestBuildError
	}
	RequestInstance.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Atmosphere-OSINT-Tool/1.0)")

	Response, RequestError := Service.HttpClient.Do(RequestInstance)
	if RequestError != nil {
		return model.FaviconResult{}, RequestError
	}
	defer Response.Body.Close()

	if Response.StatusCode != http.StatusOK {
		return model.FaviconResult{}, fmt.Errorf("favicon not found at %s (status %d)", FaviconUrl, Response.StatusCode)
	}

	BodyBytes, ReadError := io.ReadAll(io.LimitReader(Response.Body, 128*1024))
	if ReadError != nil && len(BodyBytes) == 0 {
		return model.FaviconResult{}, ReadError
	}

	if len(BodyBytes) == 0 {
		return model.FaviconResult{}, fmt.Errorf("favicon response was empty")
	}

	Md5Sum := md5.Sum(BodyBytes)
	Md5Hex := fmt.Sprintf("%x", Md5Sum)

	Base64Encoded := base64.StdEncoding.EncodeToString(BodyBytes)
	Mmh3Hash := ComputeMurmurHash3(Base64Encoded)

	return model.FaviconResult{
		Url:           CleanUrl,
		FaviconUrl:    FaviconUrl,
		Md5Hash:       Md5Hex,
		Mmh3Hash:      Mmh3Hash,
		SizeBytes:     len(BodyBytes),
		ShodanQueryUrl: fmt.Sprintf("https://www.shodan.io/search?query=http.favicon.hash%%3A%d", Mmh3Hash),
	}, nil
}

func ComputeMurmurHash3(InputText string) int32 {
	InputBytes := []byte(InputText)
	Length := len(InputBytes)

	const CConstant uint32 = 0xcc9e2d51
	const DConstant uint32 = 0x1b873593
	var Seed uint32 = 0
	Hash := Seed

	RoundedEnd := Length - (Length % 4)
	for Index := 0; Index < RoundedEnd; Index += 4 {
		Block := uint32(InputBytes[Index]) | uint32(InputBytes[Index+1])<<8 | uint32(InputBytes[Index+2])<<16 | uint32(InputBytes[Index+3])<<24

		Block *= CConstant
		Block = (Block << 15) | (Block >> 17)
		Block *= DConstant

		Hash ^= Block
		Hash = (Hash << 13) | (Hash >> 19)
		Hash = Hash*5 + 0xe6546b64
	}

	var TailBlock uint32
	TailIndex := RoundedEnd
	switch Length & 3 {
	case 3:
		TailBlock ^= uint32(InputBytes[TailIndex+2]) << 16
		fallthrough
	case 2:
		TailBlock ^= uint32(InputBytes[TailIndex+1]) << 8
		fallthrough
	case 1:
		TailBlock ^= uint32(InputBytes[TailIndex])
		TailBlock *= CConstant
		TailBlock = (TailBlock << 15) | (TailBlock >> 17)
		TailBlock *= DConstant
		Hash ^= TailBlock
	}

	Hash ^= uint32(Length)
	Hash ^= Hash >> 16
	Hash *= 0x85ebca6b
	Hash ^= Hash >> 13
	Hash *= 0xc2b2ae35
	Hash ^= Hash >> 16

	return int32(Hash)
}
