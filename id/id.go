package id

import (
	"github.com/google/uuid"
	"github.com/garnet-org/api/types/errs"
)

func Valid(s string) bool {
	return uuid.Validate(s) == nil
}

func Validate(s string) error {
	if err := uuid.Validate(s); err != nil {
		return errs.InvalidArgumentError("invalid id")
	}

	return nil
}

func Generate() (string, error) {
	v, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return v.String(), nil
}
