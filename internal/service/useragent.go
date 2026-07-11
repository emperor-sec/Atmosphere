package service

import (
	"regexp"
	"strings"

	"atmosphere/internal/model"
)

type UserAgentService struct{}

func NewUserAgentService() *UserAgentService {
	return &UserAgentService{}
}

var BrowserPatternList = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"Edge", regexp.MustCompile(`Edg(?:A|iOS)?/([\d.]+)`)},
	{"Opera", regexp.MustCompile(`(?:Opera|OPR)/([\d.]+)`)},
	{"Samsung Internet", regexp.MustCompile(`SamsungBrowser/([\d.]+)`)},
	{"Brave", regexp.MustCompile(`Brave/([\d.]+)`)},
	{"Vivaldi", regexp.MustCompile(`Vivaldi/([\d.]+)`)},
	{"UC Browser", regexp.MustCompile(`UCBrowser/([\d.]+)`)},
	{"Firefox", regexp.MustCompile(`Firefox/([\d.]+)`)},
	{"Chrome", regexp.MustCompile(`Chrome/([\d.]+)`)},
	{"Chromium", regexp.MustCompile(`Chromium/([\d.]+)`)},
	{"Safari", regexp.MustCompile(`Version/([\d.]+).*Safari`)},
	{"Internet Explorer", regexp.MustCompile(`(?:MSIE |rv:)([\d.]+)`)},
}

var OsPatternList = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"Windows 11", regexp.MustCompile(`Windows NT 10\.0.*(?:22\d{2}|Win64.*22)`)},
	{"Windows 10", regexp.MustCompile(`Windows NT 10\.0`)},
	{"Windows 8.1", regexp.MustCompile(`Windows NT 6\.3`)},
	{"Windows 8", regexp.MustCompile(`Windows NT 6\.2`)},
	{"Windows 7", regexp.MustCompile(`Windows NT 6\.1`)},
	{"Windows Vista", regexp.MustCompile(`Windows NT 6\.0`)},
	{"Windows XP", regexp.MustCompile(`Windows NT 5\.1|Windows NT 5\.2`)},
	{"macOS", regexp.MustCompile(`Mac OS X ([\d_]+)`)},
	{"iOS", regexp.MustCompile(`(?:iPhone|iPad|iPod).*OS ([\d_]+)`)},
	{"Android", regexp.MustCompile(`Android ([\d.]+)`)},
	{"Ubuntu", regexp.MustCompile(`Ubuntu`)},
	{"Fedora", regexp.MustCompile(`Fedora`)},
	{"Linux", regexp.MustCompile(`Linux`)},
	{"Chrome OS", regexp.MustCompile(`CrOS`)},
}

var EnginePatternList = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"Blink", regexp.MustCompile(`Chrome/([\d.]+)`)},
	{"Gecko", regexp.MustCompile(`Gecko/([\d.]+)`)},
	{"WebKit", regexp.MustCompile(`AppleWebKit/([\d.]+)`)},
	{"Trident", regexp.MustCompile(`Trident/([\d.]+)`)},
}

var BotPattern = regexp.MustCompile(`(?i)bot|crawler|spider|slurp|bingpreview|facebookexternalhit|whatsapp|telegrambot`)

func (Service *UserAgentService) ParseUserAgent(RawUserAgent string) model.DeviceInfo {
	Info := model.DeviceInfo{
		BrowserName:    "Unknown",
		BrowserVersion: "Unknown",
		OsName:         "Unknown",
		OsVersion:      "Unknown",
		DeviceType:     "Unknown",
		DeviceVendor:   "Unknown",
		DeviceModel:    "Unknown",
		EngineName:     "Unknown",
		EngineVersion:  "Unknown",
	}

	if RawUserAgent == "" {
		return Info
	}

	Info.IsBot = BotPattern.MatchString(RawUserAgent)

	for _, Entry := range BrowserPatternList {
		Match := Entry.Pattern.FindStringSubmatch(RawUserAgent)
		if len(Match) > 0 {
			Info.BrowserName = Entry.Name
			if len(Match) > 1 {
				Info.BrowserVersion = Match[1]
			}
			break
		}
	}

	for _, Entry := range OsPatternList {
		Match := Entry.Pattern.FindStringSubmatch(RawUserAgent)
		if Match != nil {
			Info.OsName = Entry.Name
			if len(Match) > 1 {
				Info.OsVersion = strings.ReplaceAll(Match[1], "_", ".")
			} else {
				Info.OsVersion = "N/A"
			}
			break
		}
	}

	for _, Entry := range EnginePatternList {
		Match := Entry.Pattern.FindStringSubmatch(RawUserAgent)
		if len(Match) > 1 {
			Info.EngineName = Entry.Name
			Info.EngineVersion = Match[1]
			break
		}
	}

	Service.ResolveDeviceCategory(RawUserAgent, &Info)
	Service.ResolveDeviceVendor(RawUserAgent, &Info)

	return Info
}

func (Service *UserAgentService) ResolveDeviceCategory(RawUserAgent string, Info *model.DeviceInfo) {
	LowerAgent := strings.ToLower(RawUserAgent)

	IsTabletMatch := strings.Contains(LowerAgent, "ipad") ||
		(strings.Contains(LowerAgent, "android") && !strings.Contains(LowerAgent, "mobile")) ||
		strings.Contains(LowerAgent, "tablet") ||
		strings.Contains(LowerAgent, "kindle") ||
		strings.Contains(LowerAgent, "playbook")

	IsMobileMatch := strings.Contains(LowerAgent, "mobile") ||
		strings.Contains(LowerAgent, "iphone") ||
		strings.Contains(LowerAgent, "ipod") ||
		(strings.Contains(LowerAgent, "android") && strings.Contains(LowerAgent, "mobile")) ||
		strings.Contains(LowerAgent, "windows phone") ||
		strings.Contains(LowerAgent, "blackberry")

	switch {
	case IsTabletMatch:
		Info.DeviceType = "Tablet"
		Info.IsTablet = true
	case IsMobileMatch:
		Info.DeviceType = "Mobile"
		Info.IsMobile = true
	default:
		Info.DeviceType = "Desktop"
		Info.IsDesktop = true
	}

	if Info.IsBot {
		Info.DeviceType = "Bot"
		Info.IsMobile = false
		Info.IsTablet = false
		Info.IsDesktop = false
	}
}

func (Service *UserAgentService) ResolveDeviceVendor(RawUserAgent string, Info *model.DeviceInfo) {
	LowerAgent := strings.ToLower(RawUserAgent)

	VendorMap := []struct {
		Keyword string
		Vendor  string
	}{
		{"iphone", "Apple"},
		{"ipad", "Apple"},
		{"ipod", "Apple"},
		{"macintosh", "Apple"},
		{"samsung", "Samsung"},
		{"sm-", "Samsung"},
		{"pixel", "Google"},
		{"huawei", "Huawei"},
		{"xiaomi", "Xiaomi"},
		{"redmi", "Xiaomi"},
		{"oppo", "Oppo"},
		{"vivo", "Vivo"},
		{"oneplus", "OnePlus"},
		{"realme", "Realme"},
		{"nokia", "Nokia"},
		{"lg-", "LG"},
		{"sony", "Sony"},
		{"asus", "Asus"},
		{"lenovo", "Lenovo"},
	}

	for _, Entry := range VendorMap {
		if strings.Contains(LowerAgent, Entry.Keyword) {
			Info.DeviceVendor = Entry.Vendor
			break
		}
	}

	ModelPattern := regexp.MustCompile(`\(([^;]+;\s*){1,2}([^;)]+)\)`)
	Match := ModelPattern.FindStringSubmatch(RawUserAgent)
	if len(Match) > 2 && Info.DeviceType == "Mobile" {
		Info.DeviceModel = strings.TrimSpace(Match[2])
	}
}
