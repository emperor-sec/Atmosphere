package main

import (
	"log"
	"net/http"
	"os"

	"atmosphere/internal/handler"
	"atmosphere/internal/middleware"
	"atmosphere/internal/service"
)

func main() {
	ServerPort := os.Getenv("ATMOSPHERE_PORT")
	if ServerPort == "" {
		ServerPort = "8080"
	}

	GeoService := service.NewGeoLocateService()
	UserAgentService := service.NewUserAgentService()
	DnsService := service.NewDnsResolveService()
	SslCheckService := service.NewSslCheckService()
	WhoisService := service.NewWhoisService()
	HeaderInspectService := service.NewHeaderInspectService()
	TechDetectService := service.NewTechDetectService()
	BlacklistService := service.NewBlacklistService()
	PreviewService := service.NewPreviewService()
	SubdomainService := service.NewSubdomainService()
	FaviconService := service.NewFaviconService()
	RedirectTraceService := service.NewRedirectTraceService()

	ApiHandlerInstance := handler.NewApiHandler(
		GeoService, UserAgentService, DnsService, SslCheckService, WhoisService, HeaderInspectService,
		TechDetectService, BlacklistService, PreviewService, SubdomainService, FaviconService, RedirectTraceService,
	)

	PageHandlerInstance, TemplateError := handler.NewPageHandler("web/templates/index.html")
	if TemplateError != nil {
		log.Fatalf("Failed to load template: %v", TemplateError)
	}

	Router := http.NewServeMux()
	Router.HandleFunc("/", PageHandlerInstance.HandleIndex)
	Router.HandleFunc("/api/report", ApiHandlerInstance.HandleReport)
	Router.HandleFunc("/api/lookup", ApiHandlerInstance.HandleLookup)
	Router.HandleFunc("/api/batch-lookup", ApiHandlerInstance.HandleBatchLookup)
	Router.HandleFunc("/api/dns-resolve", ApiHandlerInstance.HandleDnsResolve)
	Router.HandleFunc("/api/reverse-dns", ApiHandlerInstance.HandleReverseDns)
	Router.HandleFunc("/api/port-check", ApiHandlerInstance.HandlePortCheck)
	Router.HandleFunc("/api/ssl-check", ApiHandlerInstance.HandleSslCheck)
	Router.HandleFunc("/api/whois", ApiHandlerInstance.HandleWhoisLookup)
	Router.HandleFunc("/api/header-inspect", ApiHandlerInstance.HandleHeaderInspect)
	Router.HandleFunc("/api/dns-records", ApiHandlerInstance.HandleDnsRecords)
	Router.HandleFunc("/api/ping", ApiHandlerInstance.HandlePing)
	Router.HandleFunc("/api/tech-detect", ApiHandlerInstance.HandleTechDetect)
	Router.HandleFunc("/api/blacklist-check", ApiHandlerInstance.HandleBlacklistCheck)
	Router.HandleFunc("/api/preview", ApiHandlerInstance.HandlePreview)
	Router.HandleFunc("/api/subdomain-enum", ApiHandlerInstance.HandleSubdomainEnum)
	Router.HandleFunc("/api/favicon-lookup", ApiHandlerInstance.HandleFaviconLookup)
	Router.HandleFunc("/api/redirect-trace", ApiHandlerInstance.HandleRedirectTrace)

	StaticFileServer := http.FileServer(http.Dir("web/static"))
	Router.Handle("/static/", middleware.NoCacheStatic(http.StripPrefix("/static/", StaticFileServer)))

	WrappedRouter := middleware.SecurityHeaders(middleware.RequestLogger(Router))

	log.Printf("Atmosphere server starting on port %s", ServerPort)
	ServerError := http.ListenAndServe(":"+ServerPort, WrappedRouter)
	if ServerError != nil {
		log.Fatalf("Server failed: %v", ServerError)
	}
}
