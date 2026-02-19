// Package validator provides a simple validation mechanism to collect and report validation errors.
package validator

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
	return v.Message
}

func (v *Validator) AsError() error {
	if !v.OK() {
		return v
	}

	return nil
}
