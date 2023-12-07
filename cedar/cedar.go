//go:generate cd lib/cedar && cargo -C build --release
package cedar

/*
#cgo LDFLAGS: -L${SRCDIR}/lib/cedar/target/release -lcedar -ldl
#include "./lib/cedar.h"
*/
import "C"
import (
	"encoding/json"
	"errors"
	"runtime"
	"unsafe"
)

// Request represents a Cedar authorization (P, A, R, C) authorization request.
type Request struct {
	Principal any `json:"principal,omitempty"`
	Action    any `json:"action,omitempty"`
	Resource  any `json:"resource,omitempty"`
	Context   any `json:"context,omitempty"`
	Entities  any `json:"entities,omitempty"`
}

// ...there _must_ be a better way to do this.
func cindex[T any](ptr *T, i int) T {
	return *(&(*[100000000000]T)(unsafe.Pointer(ptr))[i])
}

func newString(c C.RawString) string {
	if c.ptr == nil {
		return ""
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(c.ptr)), (C.int)(c.len))
}

func IsAuthorized(request Request, policies string, schema any) (bool, []string, []Diagnostic, error) {
	type recvdSlice struct {
		Policies string `json:"policies"`
		Entities any    `json:"entities"`
	}

	type authorizationCall struct {
		Principal any        `json:"principal,omitempty"`
		Action    any        `json:"action"`
		Resource  any        `json:"resource,omitempty"`
		Context   any        `json:"context"`
		Schema    any        `json:"schema,omitempty"`
		Slice     recvdSlice `json:"slice"`
	}

	type authorizationResult struct {
		Success    string   `json:"success"`
		Result     string   `json:"result,omitempty"`
		IsInternal bool     `json:"isInternal,omitempty"`
		Errors     []string `json:"errors,omitempty"`
	}

	type authorizationDiagnostics struct {
		Reason []string `json:"reason"`
		Errors []string `json:"errors"`
	}

	type authorizationResponse struct {
		Decision    string                   `json:"decision"`
		Diagnostics authorizationDiagnostics `json:"diagnostics"`
	}

	context := request.Context
	if context == nil {
		context = map[string]any{}
	}
	entities := request.Entities
	if entities == nil {
		entities = map[string]any{}
	}

	b, err := json.Marshal(authorizationCall{
		Principal: request.Principal,
		Action:    request.Action,
		Resource:  request.Resource,
		Context:   context,
		Schema:    schema,
		Slice: recvdSlice{
			Policies: policies,
			Entities: entities,
		},
	})
	if err != nil {
		return false, nil, nil, err
	}

	cinput := C.CString(string(b))
	defer C.free(unsafe.Pointer(cinput))

	rawResult := C.json_is_authorized(cinput)
	defer C.free_string(rawResult)

	var result authorizationResult
	if err := json.Unmarshal(C.GoBytes(unsafe.Pointer(rawResult.ptr), C.int(rawResult.len)), &result); err != nil {
		return false, nil, nil, err
	}
	if result.Success != "true" {
		if len(result.Errors) == 0 {
			return false, nil, nil, errors.New("unknown error")
		}
		errs := make([]error, len(result.Errors))
		for i, e := range result.Errors {
			errs[i] = errors.New(e)
		}
		return false, nil, nil, errors.Join(errs...)
	}

	var response authorizationResponse
	if err := json.Unmarshal([]byte(result.Result), &response); err != nil {
		return false, nil, nil, err
	}

	if len(response.Diagnostics.Errors) != 0 {
		diags := make([]Diagnostic, len(response.Diagnostics.Errors))
		for i, err := range response.Diagnostics.Errors {
			diags[i] = Diagnostic{
				labels:   []LabeledSpan{{label: err}},
				severity: "Error",
			}
		}
		return false, nil, diags, nil
	}

	return response.Decision == "Allow", response.Diagnostics.Reason, nil, nil
}

type LabeledSpan struct {
	label  string
	offset int
	len    int
}

func (l LabeledSpan) Label() string {
	return l.label
}

func (l LabeledSpan) Offset() int {
	return l.offset
}

func (l LabeledSpan) Len() int {
	return l.len
}

type Diagnostic struct {
	code     string
	labels   []LabeledSpan
	severity string
	help     string
	url      string
}

func (d Diagnostic) Code() string {
	return d.code
}

func (d Diagnostic) Labels() []LabeledSpan {
	return d.labels
}

func (d Diagnostic) Severity() string {
	return d.severity
}

func (d Diagnostic) Help() string {
	return d.help
}

func (d Diagnostic) URL() string {
	return d.url
}

func newDiagnostics(c C.Diagnostics) []Diagnostic {
	if c.len == 0 {
		return nil
	}

	diags := make([]Diagnostic, c.len)
	for i := range diags {
		cdiag := cindex(c.ptr, i)

		var labels []LabeledSpan
		if clabels := cdiag.labels; clabels.len != 0 {
			labels = make([]LabeledSpan, clabels.len)
			for i := range labels {
				clabel := cindex(clabels.ptr, i)
				labels[i] = LabeledSpan{label: newString(clabel.text), offset: int(clabel.offset), len: int(clabel.len)}
			}
		}

		var severity string
		switch cdiag.severity {
		case 1:
			severity = "Advice"
		case 2:
			severity = "Warning"
		case 3:
			severity = "Error"
		}

		diags[i] = Diagnostic{
			code:     newString(cdiag.code),
			labels:   labels,
			severity: severity,
			help:     newString(cdiag.help),
			url:      newString(cdiag.url),
		}
	}
	return diags
}

type PolicySet struct {
	c C.PolicySet
}

func (p *PolicySet) finalize() {
	C.free_policy_set(p.c)
}

func ParsePolicies(input string) (*PolicySet, []Diagnostic) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))

	var c C.PolicySet
	cdiags := C.parse_policies(cinput, &c)
	defer C.free_diagnostics(cdiags)

	var set *PolicySet
	if c.ptr != nil {
		set = &PolicySet{c: c}
		runtime.SetFinalizer(set, (*PolicySet).finalize)
	}

	return set, newDiagnostics(cdiags)
}

type Schema struct {
	c C.Schema
}

func (s *Schema) finalize() {
	C.free_schema(s.c)
}

func ParseSchema(input string) (*Schema, []Diagnostic) {
	cinput := C.CString(input)
	defer C.free(unsafe.Pointer(cinput))

	var c C.Schema
	cdiags := C.parse_schema(cinput, &c)
	defer C.free_diagnostics(cdiags)

	var s *Schema
	if c.ptr != nil {
		s = &Schema{c: c}
		runtime.SetFinalizer(s, (*Schema).finalize)
	}

	return s, newDiagnostics(cdiags)
}

type Validator struct {
	c C.Validator
}

func NewValidator(s *Schema) *Validator {
	c := C.new_validator(s.c)
	v := &Validator{c: c}
	runtime.SetFinalizer(v, (*Validator).finalize)
	return v
}

func (v *Validator) finalize() {
	C.free_validator(v.c)
}

func (v *Validator) Validate(policySet *PolicySet) []Diagnostic {
	cdiags := C.validate(v.c, policySet.c)
	defer C.free_diagnostics(cdiags)
	return newDiagnostics(cdiags)
}

type Authorizer struct {
	c C.Authorizer
}

func NewAuthorizer() *Authorizer {
	c := C.new_authorizer()
	a := &Authorizer{c: c}
	runtime.SetFinalizer(a, (*Authorizer).finalize)
	return a
}

func (a *Authorizer) finalize() {
	C.free_authorizer(a.c)
}

func (a *Authorizer) IsAuthorized(r Request, p *PolicySet, s *Schema) (bool, []string, []Diagnostic, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return false, nil, nil, err
	}

	cinput := C.CString(string(b))
	defer C.free(unsafe.Pointer(cinput))

	c, cdiags := a.isAuthorized(unsafe.Pointer(cinput), p, s)
	defer C.free_diagnostics(cdiags)
	defer C.free_raw_strings(c.reasons)

	var reasons []string
	if c.reasons.len != 0 {
		reasons = make([]string, c.reasons.len)
		for i := range reasons {
			reasons[i] = newString(cindex(c.reasons.ptr, i))
		}
	}

	return bool(c.allow), reasons, newDiagnostics(cdiags), nil
}

func (a *Authorizer) isAuthorized(req unsafe.Pointer, p *PolicySet, s *Schema) (decision C.Decision, diags C.Diagnostics) {
	var sc C.Schema
	if s != nil {
		sc = s.c
	}

	diags = C.is_authorized(a.c, (*C.char)(req), p.c, sc, &decision)
	return
}
