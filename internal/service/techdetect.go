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

type TechDetectService struct {
	HttpClient *http.Client
}

func NewTechDetectService() *TechDetectService {
	return &TechDetectService{
		HttpClient: &http.Client{Timeout: 8 * time.Second},
	}
}

type TechSignature struct {
	Name     string
	Category string
	Pattern  *regexp.Regexp
	HeaderKey string
}

var TechSignatureList = []TechSignature{
	{"WordPress", "CMS", regexp.MustCompile(`(?i)wp-content|wp-includes|/wp-json/`), ""},
	{"Shopify", "E-Commerce", regexp.MustCompile(`(?i)cdn\.shopify\.com|Shopify\.theme`), ""},
	{"Wix", "Website Builder", regexp.MustCompile(`(?i)static\.wixstatic\.com|_wixCIDX`), ""},
	{"Squarespace", "Website Builder", regexp.MustCompile(`(?i)static1\.squarespace\.com`), ""},
	{"Drupal", "CMS", regexp.MustCompile(`(?i)Drupal\.settings|/sites/default/files/`), ""},
	{"Joomla", "CMS", regexp.MustCompile(`(?i)/media/jui/|Joomla!`), ""},
	{"Magento", "E-Commerce", regexp.MustCompile(`(?i)Mage\.Cookies|/skin/frontend/`), ""},
	{"Ghost", "CMS", regexp.MustCompile(`(?i)ghost-url|/ghost/api/`), ""},
	{"Webflow", "Website Builder", regexp.MustCompile(`(?i)webflow\.com|data-wf-site`), ""},
	{"React", "Frontend Framework", regexp.MustCompile(`(?i)__REACT_DEVTOOLS|react-dom|_reactRootContainer`), ""},
	{"Vue.js", "Frontend Framework", regexp.MustCompile(`(?i)__vue__|Vue\.config|data-v-app`), ""},
	{"Angular", "Frontend Framework", regexp.MustCompile(`(?i)ng-version|ng-app|angular\.js`), ""},
	{"Next.js", "Frontend Framework", regexp.MustCompile(`(?i)__NEXT_DATA__|/_next/static/`), ""},
	{"Nuxt.js", "Frontend Framework", regexp.MustCompile(`(?i)__NUXT__|/_nuxt/`), ""},
	{"Svelte", "Frontend Framework", regexp.MustCompile(`(?i)svelte-`), ""},
	{"jQuery", "JS Library", regexp.MustCompile(`(?i)jquery(\.min)?\.js|jQuery\.fn\.jquery`), ""},
	{"Bootstrap", "CSS Framework", regexp.MustCompile(`(?i)bootstrap(\.min)?\.css|bootstrap(\.min)?\.js`), ""},
	{"Tailwind CSS", "CSS Framework", regexp.MustCompile(`(?i)tailwindcss|tailwind\.min\.css`), ""},
	{"Google Analytics", "Analytics", regexp.MustCompile(`(?i)www\.google-analytics\.com|gtag\(|ga\('create'`), ""},
	{"Google Tag Manager", "Analytics", regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`), ""},
	{"Facebook Pixel", "Analytics", regexp.MustCompile(`(?i)connect\.facebook\.net.*fbevents\.js|fbq\('init'`), ""},
	{"Hotjar", "Analytics", regexp.MustCompile(`(?i)static\.hotjar\.com`), ""},
	{"Cloudflare", "CDN / Security", regexp.MustCompile(`(?i)cloudflare`), "Server"},
	{"Amazon CloudFront", "CDN", regexp.MustCompile(`(?i)cloudfront`), "Via"},
	{"Vercel", "Hosting", regexp.MustCompile(`(?i)vercel`), "Server"},
	{"Netlify", "Hosting", regexp.MustCompile(`(?i)netlify`), "Server"},
	{"Nginx", "Web Server", regexp.MustCompile(`(?i)nginx`), "Server"},
	{"Apache", "Web Server", regexp.MustCompile(`(?i)apache`), "Server"},
	{"PHP", "Programming Language", regexp.MustCompile(`(?i)php`), "X-Powered-By"},
	{"ASP.NET", "Programming Language", regexp.MustCompile(`(?i)asp\.net`), "X-Powered-By"},
	{"Express", "Backend Framework", regexp.MustCompile(`(?i)express`), "X-Powered-By"},
	{"Stripe", "Payments", regexp.MustCompile(`(?i)js\.stripe\.com`), ""},
	{"reCAPTCHA", "Security", regexp.MustCompile(`(?i)www\.google\.com/recaptcha`), ""},
	{"Font Awesome", "Icon Library", regexp.MustCompile(`(?i)font-?awesome`), ""},
}

func (Service *TechDetectService) DetectStack(TargetUrl string) (model.TechDetectResult, error) {
	CleanUrl := strings.TrimSpace(TargetUrl)
	if CleanUrl == "" {
		return model.TechDetectResult{}, fmt.Errorf("target url is required")
	}
	if !strings.HasPrefix(CleanUrl, "http://") && !strings.HasPrefix(CleanUrl, "https://") {
		CleanUrl = "https://" + CleanUrl
	}

	RequestInstance, RequestBuildError := http.NewRequest(http.MethodGet, CleanUrl, nil)
	if RequestBuildError != nil {
		return model.TechDetectResult{}, RequestBuildError
	}
	RequestInstance.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Atmosphere-OSINT-Tool/1.0)")

	Response, RequestError := Service.HttpClient.Do(RequestInstance)
	if RequestError != nil {
		return model.TechDetectResult{}, RequestError
	}
	defer Response.Body.Close()

	BodyBytes, ReadError := io.ReadAll(io.LimitReader(Response.Body, 512*1024))
	if ReadError != nil && len(BodyBytes) == 0 {
		return model.TechDetectResult{}, ReadError
	}
	BodyText := string(BodyBytes)

	var DetectedEntries []model.TechDetectEntry
	SeenNames := make(map[string]bool)

	for _, Signature := range TechSignatureList {
		if SeenNames[Signature.Name] {
			continue
		}

		Matched := false
		if Signature.HeaderKey != "" {
			HeaderValue := Response.Header.Get(Signature.HeaderKey)
			if HeaderValue != "" && Signature.Pattern.MatchString(HeaderValue) {
				Matched = true
			}
		} else if Signature.Pattern.MatchString(BodyText) {
			Matched = true
		}

		if Matched {
			DetectedEntries = append(DetectedEntries, model.TechDetectEntry{
				Name:     Signature.Name,
				Category: Signature.Category,
			})
			SeenNames[Signature.Name] = true
		}
	}

	return model.TechDetectResult{
		Url:             CleanUrl,
		DetectedEntries: DetectedEntries,
		ServerHeader:    Response.Header.Get("Server"),
		PoweredByHeader: Response.Header.Get("X-Powered-By"),
	}, nil
}
