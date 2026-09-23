// Package validator provides a simple validation mechanism to collect and report validation errors.
package validator

import (
	"slices"
	"strings"
)

type Validator struct {
	Message string              `json:"message"`
	Errors  map[string][]string `json:"errors"`
}

func New() *Validator {
	return &Validator{
		Message: "There were validation errors",
		Errors:  map[string][]string{},
	}
}

func (v *Validator) Add(field, msg string) {
	if v.Errors == nil {
		v.Errors = map[string][]string{}
	}
	v.Errors[field] = append(v.Errors[field], msg)
}

func (v *Validator) Join(another *Validator) {
	if another == nil {
		return
	}
	for field, msgs := range another.Errors {
		for _, msg := range msgs {
			v.Add(field, msg)
		}
	}
}

func (v *Validator) OK() bool {
	return len(v.Errors) == 0
}

func (v *Validator) Error() string {
	if len(v.Errors) == 0 {
		return v.Message
	}

	fields := make([]string, 0, len(v.Errors))
	for field := range v.Errors {
		fields = append(fields, field)
	}
	slices.Sort(fields)

	var sb strings.Builder
	sb.WriteString(v.Message)
	sb.WriteString(": ")
	for i, field := range fields {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(field)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(v.Errors[field], ", "))
	}

	return sb.String()
}

func (v *Validator) AsError() error {
	if !v.OK() {
		return v
	}

	return nil
}
