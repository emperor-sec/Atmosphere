package handler

import (
	"html/template"
	"net/http"
)

type PageHandler struct {
	Template *template.Template
}

func NewPageHandler(TemplatePath string) (*PageHandler, error) {
	ParsedTemplate, ParseError := template.ParseFiles(TemplatePath)
	if ParseError != nil {
		return nil, ParseError
	}
	return &PageHandler{Template: ParsedTemplate}, nil
}

func (Handler *PageHandler) HandleIndex(ResponseWriter http.ResponseWriter, Request *http.Request) {
	if Request.URL.Path != "/" {
		http.NotFound(ResponseWriter, Request)
		return
	}
	ResponseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
	Handler.Template.Execute(ResponseWriter, nil)
}
