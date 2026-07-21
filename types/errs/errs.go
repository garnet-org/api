// Package errs contains the error types returned by the control-plane.
package errs

import "errors"

var PermanentFailure = errors.New("permanent failure")

const (
	// Unauthenticated is returned when authentication fails.
	Unauthenticated = UnauthenticatedError("unauthenticated")
	// InvalidArgument is returned when an invalid argument is provided.
	InvalidArgument = InvalidArgumentError("invalid argument")
	// NotFound is returned when a resource is not found.
	NotFound = NotFoundError("not found")
	// Conflict is returned when a resource already exists.
	Conflict = ConflictError("conflict")
	// PermissionDenied is returned when a user does not have permission to perform an action.
	PermissionDenied = PermissionDeniedError("permission denied")
	// InternalServer is returned when an internal server error occurs.
	InternalServer = InternalServerError("internal server error")
	// Unavailable is returned when an upstream dependency fails.
	Unavailable = UnavailableError("service unavailable")
)

type UnauthenticatedError string

func (e UnauthenticatedError) Error() string { return string(e) }

func (e UnauthenticatedError) Is(target error) bool {
	if target == Unauthenticated {
		return true // All UnauthenticatedError types should match ErrUnauthenticated
	}
	if target, ok := target.(UnauthenticatedError); ok {
		return e == target
	}
	return false
}

// InvalidArgumentError is returned when an invalid argument is provided.
type InvalidArgumentError string

// Error implements the error interface for InvalidArgumentError.
func (e InvalidArgumentError) Error() string { return string(e) }

// Is checks if the error is of type InvalidArgumentError.
func (e InvalidArgumentError) Is(target error) bool {
	if target == InvalidArgument {
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
	if target == InternalServer {
		return true // All InternalServerError types should match ErrInternalServer
	}
	if target, ok := target.(InternalServerError); ok {
		return e == target
	}
	return false
}

// NotFoundError represents an error indicating that a resource was not found.
type NotFoundError string

// Error implements the error interface for NotFoundError.
func (e NotFoundError) Error() string { return string(e) }

// Is checks if the error is of type NotFoundError.
func (e NotFoundError) Is(target error) bool {
	if target == NotFound {
		return true
	}
	if target, ok := target.(NotFoundError); ok {
		return e == target
	}
	return false
}

// ConflictError represents an error indicating that a resource already exists.
type ConflictError string

func (e ConflictError) Error() string { return string(e) }

// Is checks if the error is of type ConflictError.
func (e ConflictError) Is(target error) bool {
	if target == Conflict {
		return true // All ConflictError types should match ErrConflict
	}
	if target, ok := target.(ConflictError); ok {
		return e == target
	}
	return false
}

// UnavailableError represents an error indicating that an upstream dependency failed.
type UnavailableError string

// Error implements the error interface for UnavailableError.
func (e UnavailableError) Error() string { return string(e) }

// Is checks if the error is of type UnavailableError.
func (e UnavailableError) Is(target error) bool {
	if target == Unavailable {
		return true // All UnavailableError types should match Unavailable
	}
	if target, ok := target.(UnavailableError); ok {
		return e == target
	}
	return false
}

// PermissionDeniedError represents an error indicating that the user does not have permission to perform a certain action.
type PermissionDeniedError string

// Error implements the error interface for PermissionDeniedError.
// It returns the error message as a string.
func (e PermissionDeniedError) Error() string { return string(e) }

// Is checks if the error is of type PermissionDeniedError.
func (e PermissionDeniedError) Is(target error) bool {
	if target == PermissionDenied {
		return true // All PermissionDeniedError types should match ErrPermissionDenied
	}
	if target, ok := target.(PermissionDeniedError); ok {
		return e == target
	}
	return false
}
