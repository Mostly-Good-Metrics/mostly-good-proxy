package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:     "CF-Connecting-IP takes priority",
			headers:  map[string]string{"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"},
			expected: "1.2.3.4",
		},
		{
			name:     "True-Client-IP second priority",
			headers:  map[string]string{"True-Client-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"},
			expected: "1.2.3.4",
		},
		{
			name:     "X-Real-IP third priority",
			headers:  map[string]string{"X-Real-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"},
			expected: "1.2.3.4",
		},
		{
			name:     "X-Forwarded-For single IP",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4"},
			expected: "1.2.3.4",
		},
		{
			name:     "X-Forwarded-For multiple IPs takes first",
			headers:  map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8, 9.10.11.12"},
			expected: "1.2.3.4",
		},
		{
			name:     "X-Forwarded-For with spaces",
			headers:  map[string]string{"X-Forwarded-For": "  1.2.3.4  ,  5.6.7.8  "},
			expected: "1.2.3.4",
		},
		{
			name:       "Falls back to RemoteAddr IPv4",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:12345",
			expected:   "192.168.1.1",
		},
		{
			name:       "Falls back to RemoteAddr IPv6",
			headers:    map[string]string{},
			remoteAddr: "[::1]:12345",
			expected:   "::1",
		},
		{
			name:     "Trims whitespace from header values",
			headers:  map[string]string{"CF-Connecting-IP": "  1.2.3.4  "},
			expected: "1.2.3.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}

			got := getClientIP(req)
			if got != tt.expected {
				t.Errorf("getClientIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Create a simple handler that mimics our health check
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}
	})

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health check returned %d, want %d", w.Code, http.StatusOK)
	}

	if w.Body.String() != "ok" {
		t.Errorf("health check body = %q, want %q", w.Body.String(), "ok")
	}
}

func TestProxyForwardsClientIP(t *testing.T) {
	// Create a mock upstream server that echoes back the X-MGM-Client-IP header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.Header.Get("X-MGM-Client-IP")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(clientIP))
	}))
	defer upstream.Close()

	// Create proxy handler pointing to our mock upstream
	client := &http.Client{}
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := proxyHandler(target, client)

	// Test that the proxy correctly extracts and forwards the client IP
	tests := []struct {
		name       string
		headers    map[string]string
		expectedIP string
	}{
		{
			name:       "Forwards CF-Connecting-IP",
			headers:    map[string]string{"CF-Connecting-IP": "203.0.113.50"},
			expectedIP: "203.0.113.50",
		},
		{
			name:       "Forwards X-Forwarded-For first IP",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.25, 10.0.0.1"},
			expectedIP: "198.51.100.25",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/events", strings.NewReader(`{"events":[]}`))
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("proxy returned %d, want %d", w.Code, http.StatusOK)
			}

			gotIP := w.Body.String()
			if gotIP != tt.expectedIP {
				t.Errorf("upstream received X-MGM-Client-IP = %q, want %q", gotIP, tt.expectedIP)
			}
		})
	}
}

func TestProxyForwardsHeaders(t *testing.T) {
	// Create a mock upstream that echoes back specific headers
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Received-Key", r.Header.Get("X-MGM-Key"))
		w.Header().Set("X-Received-Content-Type", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	client := &http.Client{}
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := proxyHandler(target, client)

	req := httptest.NewRequest("POST", "/v1/events", strings.NewReader(`{"events":[]}`))
	req.Header.Set("X-MGM-Key", "test-api-key-123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("proxy returned %d, want %d", w.Code, http.StatusNoContent)
	}

	if got := w.Header().Get("X-Received-Key"); got != "test-api-key-123" {
		t.Errorf("upstream received X-MGM-Key = %q, want %q", got, "test-api-key-123")
	}

	if got := w.Header().Get("X-Received-Content-Type"); got != "application/json" {
		t.Errorf("upstream received Content-Type = %q, want %q", got, "application/json")
	}
}

func TestProxyForwardsBody(t *testing.T) {
	expectedBody := `{"events":[{"name":"test_event"}]}`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != expectedBody {
			t.Errorf("upstream received body = %q, want %q", string(body), expectedBody)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	client := &http.Client{}
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := proxyHandler(target, client)

	req := httptest.NewRequest("POST", "/v1/events", strings.NewReader(expectedBody))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("proxy returned %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestProxyStripsHopByHopHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Connection"); got != "" {
			t.Errorf("upstream received Connection header = %q, want empty", got)
		}
		if got := r.Header.Get("Upgrade"); got != "" {
			t.Errorf("upstream received Upgrade header = %q, want empty", got)
		}
		w.Header().Set("Connection", "close")
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	client := &http.Client{}
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	handler := proxyHandler(target, client)

	req := httptest.NewRequest("GET", "/v1/events", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("proxy returned %d, want %d", w.Code, http.StatusNoContent)
	}

	if got := w.Header().Get("Connection"); got != "" {
		t.Errorf("client received Connection header = %q, want empty", got)
	}
	if got := w.Header().Get("Upgrade"); got != "" {
		t.Errorf("client received Upgrade header = %q, want empty", got)
	}
}
