package client

import (
	"context"
	"net/http"

	"github.com/garnet-org/api/types"
)

// IngestEvent creates or updates an event.
func (c *Client) IngestEvent(ctx context.Context, event types.CreateOrUpdateEvent) (types.EventCreatedOrUpdated, error) {
	var out types.EventCreatedOrUpdated

	return out, c.do(ctx, &out, http.MethodPut, "/api/v1/events", event)
}

// IngestEventV2 creates or updates an event using ashkaal format.
func (c *Client) IngestEventV2(ctx context.Context, event types.CreateOrUpdateEventV2) (types.EventV2CreatedOrUpdated, error) {
	var out types.EventV2CreatedOrUpdated

	return out, c.do(ctx, &out, http.MethodPut, "/api/v1/events_v2", event)
}

// Event retrieves an event by ID.
func (c *Client) Event(ctx context.Context, eventID string) (types.Event, error) {
	var result types.Event

	err := c.do(ctx, &result, http.MethodGet, "/api/v1/events/"+eventID, nil)
	if err != nil {
		return result, err
	}

	return result, nil
}
