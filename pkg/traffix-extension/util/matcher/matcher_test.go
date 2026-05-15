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

package matcher

import (
	"testing"

	v1alpha1 "github.com/openkruise/agents/api/v1alpha1"
)

func newProfileWithRules(rules []v1alpha1.SecurityRule) *v1alpha1.SecurityProfile {
	return &v1alpha1.SecurityProfile{
		Spec: v1alpha1.SecurityProfileSpec{
			Rules: rules,
		},
	}
}

func TestMatchRequest_DomainMatch(t *testing.T) {
	profile := newProfileWithRules([]v1alpha1.SecurityRule{
		{
			Name: "test-rule",
			Match: []v1alpha1.RuleMatch{
				{
					Domains: []string{"api.openai.com", "api.anthropic.com"},
				},
			},
		},
	})

	tests := []struct {
		name  string
		host  string
		match bool
	}{
		{"exact match", "api.openai.com", true},
		{"second domain match", "api.anthropic.com", true},
		{"case insensitive", "API.OPENAI.COM", true},
		{"no match", "api.example.com", false},
		{"empty host", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := RequestInfo{Host: tt.host}
			idx, matched := MatchRequest(req, profile)
			if matched != tt.match {
				t.Errorf("expected match=%v, got %v", tt.match, matched)
			}
			if matched && idx != 0 {
				t.Errorf("expected rule index 0, got %d", idx)
			}
		})
	}
}

func TestMatchRequest_PathMatch(t *testing.T) {
	profile := newProfileWithRules([]v1alpha1.SecurityRule{
		{
			Name: "path-rule",
			Match: []v1alpha1.RuleMatch{
				{
					Paths: []v1alpha1.PathMatch{
						{Type: v1alpha1.PathMatchTypePrefix, Value: "/v1/chat"},
						{Type: v1alpha1.PathMatchTypeExact, Value: "/health"},
					},
				},
			},
		},
	})

	tests := []struct {
		name  string
		path  string
		match bool
	}{
		{"prefix match", "/v1/chat/completions", true},
		{"prefix match exact boundary", "/v1/chat", true},
		{"exact match", "/health", true},
		{"no match", "/v2/models", false},
		{"similar but not prefix", "/v1/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := RequestInfo{Path: tt.path}
			_, matched := MatchRequest(req, profile)
			if matched != tt.match {
				t.Errorf("path %q: expected match=%v, got %v", tt.path, tt.match, matched)
			}
		})
	}
}

func TestMatchRequest_PathRegex(t *testing.T) {
	profile := newProfileWithRules([]v1alpha1.SecurityRule{
		{
			Name: "regex-rule",
			Match: []v1alpha1.RuleMatch{
				{
					Paths: []v1alpha1.PathMatch{
						{Type: v1alpha1.PathMatchTypeRegex, Value: `^/api/v\d+/users$`},
					},
				},
			},
		},
	})

	tests := []struct {
		name  string
		path  string
		match bool
	}{
		{"regex match v1", "/api/v1/users", true},
		{"regex match v2", "/api/v2/users", true},
		{"no match missing users", "/api/v1/groups", false},
		{"invalid path", "/api/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := RequestInfo{Path: tt.path}
			_, matched := MatchRequest(req, profile)
			if matched != tt.match {
				t.Errorf("path %q: expected match=%v, got %v", tt.path, tt.match, matched)
			}
		})
	}
}

func TestMatchRequest_MethodMatch(t *testing.T) {
	profile := newProfileWithRules([]v1alpha1.SecurityRule{
		{
			Name: "method-rule",
			Match: []v1alpha1.RuleMatch{
				{
					Methods: []string{"POST", "PUT"},
				},
			},
		},
	})

	tests := []struct {
		name   string
		method string
		match  bool
	}{
		{"exact match POST", "POST", true},
		{"exact match PUT", "PUT", true},
		{"case insensitive", "post", true},
		{"no match", "GET", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := RequestInfo{Method: tt.method}
			_, matched := MatchRequest(req, profile)
			if matched != tt.match {
				t.Errorf("method %q: expected match=%v, got %v", tt.method, tt.match, matched)
			}
		})
	}
}

func TestMatchRequest_CombinedMatch(t *testing.T) {
	profile := newProfileWithRules([]v1alpha1.SecurityRule{
		{
			Name: "combined-rule",
			Match: []v1alpha1.RuleMatch{
				{
					Domains: []string{"api.openai.com"},
					Paths: []v1alpha1.PathMatch{
						{Type: v1alpha1.PathMatchTypePrefix, Value: "/v1/"},
					},
					Methods: []string{"POST"},
				},
			},
		},
	})

	tests := []struct {
		name  string
		req   RequestInfo
		match bool
	}{
		{
			"all conditions met",
			RequestInfo{Host: "api.openai.com", Path: "/v1/chat/completions", Method: "POST"},
			true,
		},
		{
			"wrong domain",
			RequestInfo{Host: "api.example.com", Path: "/v1/chat", Method: "POST"},
			false,
		},
		{
			"wrong path",
			RequestInfo{Host: "api.openai.com", Path: "/v2/models", Method: "POST"},
			false,
		},
		{
			"wrong method",
			RequestInfo{Host: "api.openai.com", Path: "/v1/chat", Method: "GET"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, matched := MatchRequest(tt.req, profile)
			if matched != tt.match {
				t.Errorf("expected match=%v, got %v", tt.match, matched)
			}
		})
	}
}

func TestMatchRequest_MultipleMatchConditions(t *testing.T) {
	profile := newProfileWithRules([]v1alpha1.SecurityRule{
		{
			Name: "multi-match-rule",
			Match: []v1alpha1.RuleMatch{
				{Domains: []string{"api.openai.com"}, Methods: []string{"POST"}},
				{Domains: []string{"api.anthropic.com"}, Methods: []string{"POST"}},
			},
		},
	})

	req1 := RequestInfo{Host: "api.openai.com", Method: "POST"}
	_, matched1 := MatchRequest(req1, profile)
	if !matched1 {
		t.Error("expected first condition to match")
	}

	req2 := RequestInfo{Host: "api.anthropic.com", Method: "POST"}
	_, matched2 := MatchRequest(req2, profile)
	if !matched2 {
		t.Error("expected second condition to match")
	}

	req3 := RequestInfo{Host: "api.example.com", Method: "POST"}
	_, matched3 := MatchRequest(req3, profile)
	if matched3 {
		t.Error("expected no match")
	}
}

func TestMatchRequest_MultipleRules(t *testing.T) {
	profile := newProfileWithRules([]v1alpha1.SecurityRule{
		{
			Name: "first-rule",
			Match: []v1alpha1.RuleMatch{
				{Domains: []string{"api.openai.com"}},
			},
		},
		{
			Name: "second-rule",
			Match: []v1alpha1.RuleMatch{
				{Domains: []string{"api.anthropic.com"}},
			},
		},
	})

	req := RequestInfo{Host: "api.anthropic.com"}
	idx, matched := MatchRequest(req, profile)
	if !matched {
		t.Error("expected match on second rule")
	}
	if idx != 1 {
		t.Errorf("expected rule index 1, got %d", idx)
	}
}

func TestParseRequestInfo(t *testing.T) {
	h1 := map[string]string{":authority": "api.openai.com", ":path": "/v1/chat", ":method": "POST"}
	info1 := ParseRequestInfo(h1)
	if info1.Host != "api.openai.com" {
		t.Errorf("expected host 'api.openai.com', got %q", info1.Host)
	}
	if info1.Path != "/v1/chat" {
		t.Errorf("expected path '/v1/chat', got %q", info1.Path)
	}
	if info1.Method != "POST" {
		t.Errorf("expected method 'POST', got %q", info1.Method)
	}

	h2 := map[string]string{"host": "example.com", ":path": "/api"}
	info2 := ParseRequestInfo(h2)
	if info2.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", info2.Host)
	}
}

func TestMatchRequest_NoRules(t *testing.T) {
	profile := newProfileWithRules([]v1alpha1.SecurityRule{})
	req := RequestInfo{Host: "anything"}
	_, matched := MatchRequest(req, profile)
	if matched {
		t.Error("expected no match with empty rules")
	}
}
