// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	routev1 "github.com/openshift/api/route/v1"
)

// RouteSpecApplyConfiguration represents a declarative configuration of the RouteSpec type for use
// with apply.
type RouteSpecApplyConfiguration struct {
	Host              *string                                  `json:"host,omitempty"`
	Subdomain         *string                                  `json:"subdomain,omitempty"`
	Path              *string                                  `json:"path,omitempty"`
	To                *RouteTargetReferenceApplyConfiguration  `json:"to,omitempty"`
	AlternateBackends []RouteTargetReferenceApplyConfiguration `json:"alternateBackends,omitempty"`
	Port              *RoutePortApplyConfiguration             `json:"port,omitempty"`
	TLS               *TLSConfigApplyConfiguration             `json:"tls,omitempty"`
	WildcardPolicy    *routev1.WildcardPolicyType              `json:"wildcardPolicy,omitempty"`
	HTTPHeaders       *RouteHTTPHeadersApplyConfiguration      `json:"httpHeaders,omitempty"`
}

// RouteSpecApplyConfiguration constructs a declarative configuration of the RouteSpec type for use with
// apply.
func RouteSpec() *RouteSpecApplyConfiguration {
	return &RouteSpecApplyConfiguration{}
}

// WithHost sets the Host field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Host field is set to the value of the last call.
func (b *RouteSpecApplyConfiguration) WithHost(value string) *RouteSpecApplyConfiguration {
	b.Host = &value
	return b
}

// WithSubdomain sets the Subdomain field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Subdomain field is set to the value of the last call.
func (b *RouteSpecApplyConfiguration) WithSubdomain(value string) *RouteSpecApplyConfiguration {
	b.Subdomain = &value
	return b
}

// WithPath sets the Path field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Path field is set to the value of the last call.
func (b *RouteSpecApplyConfiguration) WithPath(value string) *RouteSpecApplyConfiguration {
	b.Path = &value
	return b
}

// WithTo sets the To field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the To field is set to the value of the last call.
func (b *RouteSpecApplyConfiguration) WithTo(value *RouteTargetReferenceApplyConfiguration) *RouteSpecApplyConfiguration {
	b.To = value
	return b
}

// WithAlternateBackends adds the given value to the AlternateBackends field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the AlternateBackends field.
func (b *RouteSpecApplyConfiguration) WithAlternateBackends(values ...*RouteTargetReferenceApplyConfiguration) *RouteSpecApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithAlternateBackends")
		}
		b.AlternateBackends = append(b.AlternateBackends, *values[i])
	}
	return b
}

// WithPort sets the Port field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Port field is set to the value of the last call.
func (b *RouteSpecApplyConfiguration) WithPort(value *RoutePortApplyConfiguration) *RouteSpecApplyConfiguration {
	b.Port = value
	return b
}

// WithTLS sets the TLS field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TLS field is set to the value of the last call.
func (b *RouteSpecApplyConfiguration) WithTLS(value *TLSConfigApplyConfiguration) *RouteSpecApplyConfiguration {
	b.TLS = value
	return b
}

// WithWildcardPolicy sets the WildcardPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the WildcardPolicy field is set to the value of the last call.
func (b *RouteSpecApplyConfiguration) WithWildcardPolicy(value routev1.WildcardPolicyType) *RouteSpecApplyConfiguration {
	b.WildcardPolicy = &value
	return b
}

// WithHTTPHeaders sets the HTTPHeaders field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the HTTPHeaders field is set to the value of the last call.
func (b *RouteSpecApplyConfiguration) WithHTTPHeaders(value *RouteHTTPHeadersApplyConfiguration) *RouteSpecApplyConfiguration {
	b.HTTPHeaders = value
	return b
}
