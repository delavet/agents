/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package matcher provides request matching logic against SecurityProfile rules.
package matcher

import (
	"fmt"
	"regexp"
	"strings"

	v1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

// RequestInfo contains the extracted HTTP request attributes for matching.
type RequestInfo struct {
	// Host is the value of the Host header (or :authority pseudo-header).
	Host string
	// Path is the request path (:path pseudo-header).
	Path string
	// Method is the HTTP method (:method pseudo-header).
	Method string
}

// MatchRequest checks if the given request matches any rule in the profile.
// It returns the index of the first matching rule and true, or -1 and false if no match.
func MatchRequest(req RequestInfo, profile *v1alpha1.SecurityProfile) (int, bool) {
	for i, rule := range profile.Spec.Rules {
		if MatchesRule(req, rule) {
			return i, true
		}
	}
	return -1, false
}

// MatchesRule checks if the request matches a specific rule.
// A request matches a rule if it matches ANY of the conditions in the Match list.
func MatchesRule(req RequestInfo, rule v1alpha1.SecurityRule) bool {
	for _, matchCond := range rule.Match {
		if matchesCondition(req, matchCond) {
			return true
		}
	}
	return false
}

// matchesCondition checks if a request matches a single RuleMatch condition.
// All specified sub-conditions within a match condition must be satisfied.
func matchesCondition(req RequestInfo, match v1alpha1.RuleMatch) bool {
	if len(match.Domains) > 0 {
		if !matchDomain(req.Host, match.Domains) {
			return false
		}
	}

	if len(match.Paths) > 0 {
		if !matchPath(req.Path, match.Paths) {
			return false
		}
	}

	if len(match.Methods) > 0 {
		if !matchMethod(req.Method, match.Methods) {
			return false
		}
	}

	return true
}

// matchDomain checks if the host matches any of the domain patterns.
// Supports wildcard "*" to match any domain.
func matchDomain(host string, domains []string) bool {
	for _, domain := range domains {
		if domain == "*" {
			return true
		}
		if strings.EqualFold(host, domain) {
			return true
		}
	}
	return false
}

// matchPath checks if the path matches any of the path conditions.
func matchPath(path string, paths []v1alpha1.PathMatch) bool {
	for _, pm := range paths {
		if matchSinglePath(path, pm) {
			return true
		}
	}
	return false
}

// matchSinglePath checks if the path matches a single PathMatch condition.
func matchSinglePath(path string, pm v1alpha1.PathMatch) bool {
	switch pm.Type {
	case v1alpha1.PathMatchTypeExact:
		return path == pm.Value
	case v1alpha1.PathMatchTypePrefix:
		return strings.HasPrefix(path, pm.Value)
	case v1alpha1.PathMatchTypeRegex:
		matched, err := regexp.MatchString(pm.Value, path)
		return err == nil && matched
	default:
		return false
	}
}

// matchMethod checks if the method matches any of the allowed methods (case-insensitive).
func matchMethod(method string, methods []string) bool {
	upperMethod := strings.ToUpper(method)
	for _, m := range methods {
		if strings.EqualFold(upperMethod, m) {
			return true
		}
	}
	return false
}

// ParseRequestInfo extracts RequestInfo from Envoy header values.
// Envoy sends pseudo-headers (:method, :path, :authority) and the Host header.
// :authority is the gRPC/HTTP2 equivalent of Host.
func ParseRequestInfo(headers map[string]string) RequestInfo {
	info := RequestInfo{}

	// Check :authority first (HTTP/2 pseudo-header).
	if auth, ok := headers[":authority"]; ok && auth != "" {
		info.Host = auth
	} else if host, ok := headers["host"]; ok && host != "" {
		info.Host = host
	}

	if path, ok := headers[":path"]; ok {
		info.Path = path
	}

	if method, ok := headers[":method"]; ok {
		info.Method = method
	}

	return info
}

// ParseHeaderValue extracts a header value from the Envoy headers.
// Handles multiple representations of the same header name.
func ParseHeaderValue(headers map[string]string, name string) (string, error) {
	if val, ok := headers[name]; ok {
		return val, nil
	}
	return "", fmt.Errorf("header %q not found", name)
}
