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

// Package plugins defines the contract for traffix-extension request-handling
// plugins. The handlers package walks the rule chain and asks each registered
// plugin whether it wants to act on the rule. Plugins return a Result that
// tells the handler whether to short-circuit (Immediate), accumulate header
// mutations (Mutate), or skip (Continue).
package plugins

import (
	"context"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	"github.com/openkruise/agents/pkg/traffix-extension/framework/credential"
	"github.com/openkruise/agents/pkg/traffix-extension/util/matcher"
)

// Action is the disposition a plugin reports back to the handler.
type Action int

const (
	// ActionContinue means the plugin did not act on the rule; the handler
	// should keep walking remaining plugins / rules.
	ActionContinue Action = iota
	// ActionImmediate means the plugin produced a terminal response. The
	// handler must return Responses immediately and skip remaining plugins
	// and rules.
	ActionImmediate
	// ActionMutate means the plugin produced header mutations to apply.
	// The handler accumulates them and continues walking. The handler
	// guarantees the same plugin is invoked at most once per request in
	// this mode (first matching rule wins).
	ActionMutate
)

// Result is the value returned by a plugin's OnRequestHeaders.
type Result struct {
	Action    Action
	Responses []*extProcPb.ProcessingResponse
}

// ContinueResult is a convenience constructor for "skip" results.
func ContinueResult() Result {
	return Result{Action: ActionContinue}
}

// ImmediateResult builds a terminal result with the given responses.
func ImmediateResult(responses ...*extProcPb.ProcessingResponse) Result {
	return Result{Action: ActionImmediate, Responses: responses}
}

// MutateResult builds a header-mutation result with the given responses.
func MutateResult(responses ...*extProcPb.ProcessingResponse) Result {
	return Result{Action: ActionMutate, Responses: responses}
}

// RequestContext is the per-request data the handler hands to every plugin.
// Plugins should treat it as read-only.
type RequestContext struct {
	// Headers is the lowercase-keyed Envoy request header map.
	Headers map[string]string
	// Info is the parsed (host, path, method) tuple used for matching.
	Info matcher.RequestInfo
	// PodNN identifies the source pod (for logging).
	PodNN types.NamespacedName
	// Profile is the SecurityProfile that owns the rule being evaluated.
	Profile *v1alpha1.SecurityProfile
	// SandboxToken is the parsed filter_state['sandbox.token']. nil when
	// no sandbox token is available; plugins that require it should
	// return ActionContinue in that case unless their semantics are
	// independent of agent identity (e.g. Block).
	SandboxToken *credential.SandboxToken
	// CredClient is the credential provider client (for plugins that need
	// to fetch secondary tokens).
	CredClient *credential.Client
}

// Plugin is the interface every functional module implements.
//
// Plugins inspect a single SecurityRule on each invocation and decide whether
// they act. Implementations must be safe for concurrent use.
type Plugin interface {
	// Name returns a stable identifier (used as a per-request mutate-once
	// key). Two plugins must never share a name.
	Name() string

	// OnRequestHeaders is invoked once per matching rule per request. The
	// plugin should return ActionContinue if the rule's action is not
	// relevant to it.
	OnRequestHeaders(ctx context.Context, rctx *RequestContext, rule *v1alpha1.SecurityRule) (Result, error)
}
