// Package types contains all the required types for v2 events API using ashkaal format.
package types

import (
	"time"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
	"github.com/garnet-org/api/types/errs"
)

const (
	// ErrInvalidEventV2Kind is returned when the v2 event kind is invalid.
	ErrInvalidEventV2Kind = errs.InvalidArgumentError("invalid v2 event kind")

	// ErrIDcannotBeEmptyV2 is returned when the v2 event ID is empty.
	ErrIDcannotBeEmptyV2 = errs.InvalidArgumentError("v2 event id is required")
)

// CreateOrUpdateEventV2 is used for creating or updating v2 events in ashkaal format.
type CreateOrUpdateEventV2 struct {
	ID string `json:"id"`
	// agentID is populated from JWT token
	agentID   string        `json:"-"`
	Kind      kind.Kind     `json:"kind"`
	Data      ongoing.Base  `json:"data"`
	CreatedAt time.Time     `json:"createdAt"`
	UpdatedAt time.Time     `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateEventV2 is valid.
func (e *CreateOrUpdateEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if !isValidAshkaalKind(e.Kind) {
		return ErrInvalidEventV2Kind
	}

	return nil
}

// isValidAshkaalKind checks if the ashkaal kind.Kind is valid.
func isValidAshkaalKind(k kind.Kind) bool {
	switch k {
	case kind.KindFlows, kind.KindDetections, kind.KindInfos, kind.KindNetPolicy:
		return true
	case kind.KindNone, kind.KindEmpty:
		return false
	default:
		return false
	}
}

// EventV2 represents a v2 event with full agent details in ashkaal format.
type EventV2 struct {
	ID        string        `json:"id"`
	Agent     Agent         `json:"agent"`
	Kind      kind.Kind     `json:"kind"`
	Data      ongoing.Base  `json:"data"`
	CreatedAt time.Time     `json:"createdAt"`
	UpdatedAt time.Time     `json:"updatedAt"`
}

// Validate checks if the EventV2 is valid.
func (e *EventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if !isValidAshkaalKind(e.Kind) {
		return ErrInvalidEventV2Kind
	}

	return nil
}

// EventV2CreatedOrUpdated represents the response when a v2 event is successfully created or updated.
type EventV2CreatedOrUpdated struct {
	ID        string    `json:"id"`
	Created   bool      `json:"created"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Specific ashkaal event types for different scenarios

// CreateOrUpdateDropIPEventV2 represents a DropIP event in v2 format.
type CreateOrUpdateDropIPEventV2 struct {
	ID        string          `json:"id"`
	agentID   string          `json:"-"`
	Data      ongoing.DropIP  `json:"data"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateDropIPEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateDropIPEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateDropIPEventV2 is valid.
func (e *CreateOrUpdateDropIPEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if e.Data.IP == "" {
		return errs.InvalidArgumentError("dropip event must have an IP address")
	}

	return nil
}

// CreateOrUpdateNetworkFlowEventV2 represents a NetworkFlow event in v2 format.
type CreateOrUpdateNetworkFlowEventV2 struct {
	ID        string              `json:"id"`
	agentID   string              `json:"-"`
	Data      ongoing.NetworkFlow `json:"data"`
	CreatedAt time.Time           `json:"createdAt"`
	UpdatedAt time.Time           `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateNetworkFlowEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateNetworkFlowEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateNetworkFlowEventV2 is valid.
func (e *CreateOrUpdateNetworkFlowEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if e.Data.Flow.Proto == "" {
		return errs.InvalidArgumentError("network flow event must have a protocol")
	}

	return nil
}

// CreateOrUpdateExecutionEventV2 represents an Execution event in v2 format.
type CreateOrUpdateExecutionEventV2 struct {
	ID        string            `json:"id"`
	agentID   string            `json:"-"`
	Data      ongoing.Execution `json:"data"`
	CreatedAt time.Time         `json:"createdAt"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateExecutionEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateExecutionEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateExecutionEventV2 is valid.
func (e *CreateOrUpdateExecutionEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if e.Data.Process.Exe == "" && e.Data.Process.Cmd == "" {
		return errs.InvalidArgumentError("execution event must have an executable or command")
	}

	return nil
}

// CreateOrUpdateFileAccessEventV2 represents a FileAccess event in v2 format.
type CreateOrUpdateFileAccessEventV2 struct {
	ID        string              `json:"id"`
	agentID   string              `json:"-"`
	Data      ongoing.FileAccess  `json:"data"`
	CreatedAt time.Time           `json:"createdAt"`
	UpdatedAt time.Time           `json:"updatedAt"`
}

// AgentID returns the ID of the agent that created or updated the event.
func (e CreateOrUpdateFileAccessEventV2) AgentID() string {
	return e.agentID
}

// SetAgentID sets the ID of the agent that created or updated the event.
func (e *CreateOrUpdateFileAccessEventV2) SetAgentID(agentID string) {
	e.agentID = agentID
}

// Validate checks if the CreateOrUpdateFileAccessEventV2 is valid.
func (e *CreateOrUpdateFileAccessEventV2) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmptyV2
	}

	if e.Data.File.File == "" {
		return errs.InvalidArgumentError("file access event must have a file path")
	}

	return nil
}

// EventV2Wrapper is a wrapper struct for unmarshaling v2 events in different formats.
type EventV2Wrapper struct {
	ID   string      `json:"id"`
	Kind kind.Kind   `json:"kind"`
	Data interface{} `json:"data"`
}

// ToCreateOrUpdateEventV2 converts the wrapper to a CreateOrUpdateEventV2.
func (w *EventV2Wrapper) ToCreateOrUpdateEventV2() (*CreateOrUpdateEventV2, error) {
	event := &CreateOrUpdateEventV2{
		ID:        w.ID,
		Kind:      w.Kind,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Convert data based on kind
	switch w.Kind {
	case kind.KindFlows:
		// Try to unmarshal as different flow types
		if dropIP, ok := w.Data.(ongoing.DropIP); ok {
			event.Data = *dropIP.Base
		} else if networkFlow, ok := w.Data.(ongoing.NetworkFlow); ok {
			event.Data = *networkFlow.Base
		} else if base, ok := w.Data.(ongoing.Base); ok {
			event.Data = base
		} else {
			return nil, errs.InvalidArgumentError("invalid flow event data")
		}
	case kind.KindDetections:
		// Try to unmarshal as different detection types
		if execution, ok := w.Data.(ongoing.Execution); ok {
			event.Data = *execution.Base
		} else if fileAccess, ok := w.Data.(ongoing.FileAccess); ok {
			event.Data = *fileAccess.Base
		} else if base, ok := w.Data.(ongoing.Base); ok {
			event.Data = base
		} else {
			return nil, errs.InvalidArgumentError("invalid detection event data")
		}
	case kind.KindInfos:
		if base, ok := w.Data.(ongoing.Base); ok {
			event.Data = base
		} else {
			return nil, errs.InvalidArgumentError("invalid info event data")
		}
	case kind.KindNetPolicy:
		if base, ok := w.Data.(ongoing.Base); ok {
			event.Data = base
		} else {
			return nil, errs.InvalidArgumentError("invalid netpolicy event data")
		}
	case kind.KindNone, kind.KindEmpty:
		return nil, ErrInvalidEventV2Kind
	default:
		return nil, ErrInvalidEventV2Kind
	}

	return event, nil
}