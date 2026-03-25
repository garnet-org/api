package id

import (
	"github.com/google/uuid"
)

func Valid(s string) bool {
	return uuid.Validate(s) == nil
}
