# Atmosphere

An ethical OSINT reconnaissance panel written in Go for IP geolocation, device fingerprinting, and DNS diagnostics.

## Views

1. **Self Scan** — displays information about the device currently viewing the panel.
2. **IP Lookup** — manual geolocation lookup for any IP address, with a map preview and map links.
3. **Batch Lookup** — resolve up to 20 IP addresses in a single request.
4. **DNS Tools** — forward hostname resolution and reverse PTR lookup.
5. **About** — overview of the tool, its capabilities, and ethical use guidelines.

## Features

- Public IP resolution with automatic multi-provider geolocation fallback (ip-api.com, ipwho.is, ipapi.co) for higher reliability and accuracy
- Local IP discovery via WebRTC ICE candidates (self scan only, client-side)
- User-Agent parsing: browser name/version, OS name/version, rendering engine
- Device classification: Desktop, Mobile, Tablet, Bot, plus vendor and model detection
- Mobile network, Proxy/VPN, and Hosting/Datacenter flags where available
- Latitude/longitude coordinates with direct Google Maps and OpenStreetMap links
- Embedded interactive map rendered directly inside the panel
- Forward and reverse DNS resolution tools
- Claude-desktop-style collapsible sidebar navigation, fully responsive
- GitHub Dark themed UI, Font Awesome icons only, no emoji
- JSON export for every report type

## Note on Altitude

IP-based geolocation providers, including every provider used in this project, do not supply altitude data. Altitude requires a physical GPS sensor and explicit device permission, which falls outside what IP-to-location mapping can offer. The `Altitude` field is intentionally labeled "Not Available From IP Geolocation" rather than displaying a fabricated value.

## Ethical Use

Atmosphere does not collect data from third parties without their knowledge or consent. Every capability in this panel operates only on:

1. The visitor's own connection and browser (Self Scan)
2. An IP address, IP list, or hostname the operator explicitly enters (IP Lookup, Batch Lookup, DNS Tools)

There is no tracking-link generator, no covert capture mechanism, and no persistent storage of visitor data — reports exist only for the duration of the request. Use this tool only on systems and targets you are authorized to test.

## Project Structure

```
atmosphere/
├── cmd/
│   └── server/
│       └── main.go                  # Entry point, routing, server bootstrap
├── internal/
│   ├── handler/
│   │   ├── api.go                   # /api/report, /api/lookup, /api/batch-lookup, /api/dns-resolve, /api/reverse-dns
│   │   └── page.go                  # Serves the main panel page
│   ├── middleware/
│   │   └── logger.go                # Request logging & security headers
│   ├── model/
│   │   └── visitor.go                # All shared data structures
│   └── service/
│       ├── geolocate.go              # Multi-provider geolocation with fallback chain
│       ├── useragent.go              # Browser/OS/device parsing
│       └── dnsresolve.go             # Forward and reverse DNS resolution
├── web/
│   ├── static/
│   │   ├── css/style.css             # GitHub Dark theme, sidebar layout, responsive
│   │   ├── js/app.js                 # Client-side logic (class AtmosphereClient)
│   │   └── img/logo.svg              # Application logo
│   └── templates/
│       └── index.html                # Sidebar shell and all views
├── go.mod
└── README.md
```

## Installation & Running

Requires Go >= 1.22.

```bash
cd atmosphere
go mod tidy
go run ./cmd/server
```

The server runs on `http://localhost:8080` by default. Use a different port with an environment variable:

```bash
ATMOSPHERE_PORT=9090 go run ./cmd/server
```

Build a production binary:

```bash
go build -o atmosphere-server ./cmd/server
./atmosphere-server
```

## Endpoints

| Method | Path                | Description                                              |
|--------|---------------------|-----------------------------------------------------------|
| GET    | /                   | Main panel page                                            |
| POST   | /api/report         | Self-scan report for the requesting device                 |
| POST   | /api/lookup         | Geolocation lookup for `{"TargetIp": "8.8.8.8"}`            |
| POST   | /api/batch-lookup   | Geolocation lookup for `{"TargetIps": ["8.8.8.8", "1.1.1.1"]}` (max 20) |
| POST   | /api/dns-resolve    | Forward DNS resolution for `{"TargetHost": "example.com"}`  |
| POST   | /api/reverse-dns    | Reverse DNS/PTR lookup for `{"TargetIp": "1.1.1.1"}`         |

## Deployment Notes

If deployed behind a reverse proxy (Nginx/Caddy), ensure the `X-Forwarded-For` header is forwarded so Self Scan can accurately detect the visitor's public IP, since `service.ExtractClientIp` prioritizes that header before falling back to `RemoteAddr`.

## Credits

Developed by **MatrixTM26** — **Emperor Security Research**, for ethical offensive security and red teaming research.
