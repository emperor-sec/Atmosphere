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

	ApiHandlerInstance := handler.NewApiHandler(GeoService, UserAgentService, DnsService)

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

	StaticFileServer := http.FileServer(http.Dir("web/static"))
	Router.Handle("/static/", middleware.NoCacheStatic(http.StripPrefix("/static/", StaticFileServer)))

	WrappedRouter := middleware.SecurityHeaders(middleware.RequestLogger(Router))

	log.Printf("Atmosphere server starting on port %s", ServerPort)
	ServerError := http.ListenAndServe(":"+ServerPort, WrappedRouter)
	if ServerError != nil {
		log.Fatalf("Server failed: %v", ServerError)
	}
}
