// Package errs contains the error types returned by the jibril-server.
package errs

import "errors"

var PermanentFailure = errors.New("permanent failure")

const (
	// ErrInvalidArgument is returned when an invalid argument is provided.
	ErrInvalidArgument = InvalidArgumentError("invalid argument")

	// ErrInternalServer is returned when an internal server error occurs.
	ErrInternalServer = InternalServerError("internal server error")
)

// InvalidArgumentError is returned when an invalid argument is provided.
type InvalidArgumentError string

// Error implements the error interface for InvalidArgumentError.
func (e InvalidArgumentError) Error() string { return string(e) }

// Is checks if the error is of type InvalidArgumentError.
func (e InvalidArgumentError) Is(target error) bool {
	if target == ErrInvalidArgument {
		return true // All InvalidArgumentError types should match ErrInvalidArgument
	}
	if target, ok := target.(InvalidArgumentError); ok {
		return e == target
	}
	return false
}

// InternalServerError is returned when an internal server error occurs.
type InternalServerError string

// Error implements the error interface for InternalServerError.
func (e InternalServerError) Error() string { return string(e) }

// Is checks if the error is of type InternalServerError.
func (e InternalServerError) Is(target error) bool {
	if target == ErrInternalServer {
		return true // All InternalServerError types should match ErrInternalServer
	}
	if target, ok := target.(InternalServerError); ok {
		return e == target
	}
	return false
}

// ErrNotFound is returned when a resource is not found.
const ErrNotFound = NotFoundError("not found")

// NotFoundError represents an error indicating that a resource was not found.
type NotFoundError string

// Error implements the error interface for NotFoundError.
func (e NotFoundError) Error() string { return string(e) }

// Is checks if the error is of type NotFoundError.
func (e NotFoundError) Is(target error) bool {
	if target == ErrNotFound {
		return true
	}
	if target, ok := target.(NotFoundError); ok {
		return e == target
	}
	return false
}

// ErrUnauthorized is returned when a user is not authorized to perform an action.
const ErrUnauthorized = UnauthorizedError("unauthorized")

// UnauthorizedError represents an error indicating that the user is not authorized to perform a certain action.
type UnauthorizedError string

// Error implements the error interface for UnauthorizedError.
func (e UnauthorizedError) Error() string { return string(e) }

// Is checks if the error is of type UnauthorizedError.
func (e UnauthorizedError) Is(target error) bool {
	if target == ErrUnauthorized {
		return true // All UnauthorizedError types should match ErrUnauthorized
	}
	if target, ok := target.(UnauthorizedError); ok {
		return e == target
	}
	return false
}

// ErrConflict is returned when a resource already exists.
const ErrConflict = ConflictError("resource already exists")

// ConflictError represents an error indicating that a resource already exists.
type ConflictError string

// ConflictError represents an error indicating that a resource already exists.
func (e ConflictError) Error() string { return string(e) }

// Is checks if the error is of type ConflictError.
func (e ConflictError) Is(target error) bool {
	if target == ErrConflict {
		return true // All ConflictError types should match ErrConflict
	}
	if target, ok := target.(ConflictError); ok {
		return e == target
	}
	return false
}

// ErrPermissionDenied is returned when a user does not have permission to perform an action.
const ErrPermissionDenied = PermissionDeniedError("permission denied")

// PermissionDeniedError represents an error indicating that the user does not have permission to perform a certain action.
type PermissionDeniedError string

// Error implements the error interface for PermissionDeniedError.
// It returns the error message as a string.
func (e PermissionDeniedError) Error() string { return string(e) }

// Is checks if the error is of type PermissionDeniedError.
func (e PermissionDeniedError) Is(target error) bool {
	if target == ErrPermissionDenied {
		return true // All PermissionDeniedError types should match ErrPermissionDenied
	}
	if target, ok := target.(PermissionDeniedError); ok {
		return e == target
	}
	return false
}

func Is(err error) bool {
	return errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrInvalidArgument) ||
		errors.Is(err, ErrInternalServer) ||
		errors.Is(err, ErrConflict) ||
		errors.Is(err, ErrPermissionDenied)
}
