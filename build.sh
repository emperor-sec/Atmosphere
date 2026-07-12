#!/usr/bin/sh

go mod tidy
go build -o atmosphere ./cmd/server/main.go
chmod +x atmosphere
echo "build finished."
