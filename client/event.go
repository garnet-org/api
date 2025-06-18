package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/garnet-org/api/types"
)

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

// Events retrieves a list of events with optional filters.
func (c *Client) Events(ctx context.Context, params types.ListEvents) (types.Page[types.EventV2], error) {
	var out types.Page[types.EventV2]

	// Build query parameters
	query := url.Values{}

	if params.Filters != nil {
		if params.Filters.AgentID != nil {
			query.Set("filter.agent_id", *params.Filters.AgentID)
		}
		if params.Filters.Kind != nil {
			query.Set("filter.kind", *params.Filters.Kind)
		}
		for _, name := range params.Filters.MetadataNames {
			query.Add("filter.metadata.name", name)
		}
	}

	// Add pagination parameters
	if params.PageArgs.First != nil {
		query.Set("first", strconv.FormatUint(uint64(*params.PageArgs.First), 10))
	}
	if params.PageArgs.Last != nil {
		query.Set("last", strconv.FormatUint(uint64(*params.PageArgs.Last), 10))
	}
	if params.PageArgs.After != nil {
		query.Set("after", string(*params.PageArgs.After))
	}
	if params.PageArgs.Before != nil {
		query.Set("before", string(*params.PageArgs.Before))
	}

	// Add sorting parameters
	if params.Sort != nil {
		query.Set("sort.field", params.Sort.Field)
		query.Set("sort.order", params.Sort.Order.String())
	}

	// Make the request
	url := "/api/v1/events"
	if len(query) > 0 {
		url += "?" + query.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, url, nil)
}
