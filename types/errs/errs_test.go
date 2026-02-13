package errs_test

import (
	"errors"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/garnet-org/api/types/errs"
)

func TestNotFoundError_Is(t *testing.T) {
	err := errs.NotFoundError("resource not found")
	assert.True(t, errors.Is(err, errs.ErrNotFound), "NotFoundError should match ErrNotFound")
}
