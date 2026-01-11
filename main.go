package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	targetURL := os.Getenv("MGM_TARGET_URL")
	if targetURL == "" {
		targetURL = "https://ingest.mostlygoodmetrics.com"
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Invalid MGM_TARGET_URL: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	http.HandleFunc("/", proxyHandler(target, client))

	log.Printf("MGM Proxy starting on :%s -> %s", port, targetURL)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}

func proxyHandler(target *url.URL, client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Health check
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}

		// Get the real client IP
		clientIP := getClientIP(r)

		// Build the target URL
		targetReq, err := http.NewRequest(r.Method, target.String()+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}
		targetReq.Host = target.Host

		// Copy headers from original request, stripping hop-by-hop headers.
		copyHeaders(targetReq.Header, r.Header)

		// Set the client IP header that MGM expects
		targetReq.Header.Set("X-MGM-Client-IP", clientIP)

		// Forward the request
		resp, err := client.Do(targetReq)
		if err != nil {
			log.Printf("Proxy error: %v", err)
			http.Error(w, "Failed to reach upstream", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		copyHeaders(w.Header(), resp.Header)

		// Copy status code and body
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

// getClientIP extracts the real client IP from various headers
func getClientIP(r *http.Request) string {
	// Check common headers in order of preference
	headers := []string{
		"CF-Connecting-IP", // Cloudflare
		"True-Client-IP",   // Akamai, Cloudflare Enterprise
		"X-Real-IP",        // Nginx
		"X-Forwarded-For",  // Standard proxy header
	}

	for _, header := range headers {
		if value := r.Header.Get(header); value != "" {
			// X-Forwarded-For can contain multiple IPs; take the first one
			if header == "X-Forwarded-For" {
				parts := strings.Split(value, ",")
				return strings.TrimSpace(parts[0])
			}
			return strings.TrimSpace(value)
		}
	}

	// Fall back to RemoteAddr (strip port if present)
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		// Check if this is IPv6 (has brackets) or IPv4
		if strings.Contains(ip, "[") {
			// IPv6: [::1]:8080 -> ::1
			if bracketIdx := strings.LastIndex(ip, "]"); bracketIdx != -1 {
				ip = ip[1:bracketIdx]
			}
		} else {
			// IPv4: 127.0.0.1:8080 -> 127.0.0.1
			ip = ip[:idx]
		}
	}
	return ip
}

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func copyHeaders(dst, src http.Header) {
	connectionTokens := connectionHeaderTokens(src)

	for key, values := range src {
		canonicalKey := http.CanonicalHeaderKey(key)
		if _, ok := hopByHopHeaders[canonicalKey]; ok {
			continue
		}
		if _, ok := connectionTokens[canonicalKey]; ok {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func connectionHeaderTokens(headers http.Header) map[string]struct{} {
	tokens := make(map[string]struct{})
	if value := headers.Get("Connection"); value != "" {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			tokens[http.CanonicalHeaderKey(token)] = struct{}{}
		}
	}
	return tokens
}
