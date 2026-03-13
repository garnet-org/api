package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

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

func (c *Client) Events(ctx context.Context, in types.ListEvents) (types.CursorPage[types.Event], error) {
	var out types.CursorPage[types.Event]

	if in.ProjectID == nil && in.AgentID == nil {
		return out, errors.New("at least one of project_id or agent_id must be provided")
	}

	q := url.Values{}
	for _, kind := range in.Kinds {
		q.Add("kinds", kind.String())
	}

	for _, name := range in.Names {
		q.Add("names", name)
	}

	for _, cluster := range in.KubernetesClusters {
		q.Add("kubernetes_clusters", cluster)
	}

	for _, namespace := range in.KubernetesNamespaces {
		q.Add("kubernetes_namespaces", namespace)
	}

	for _, node := range in.KubernetesNodes {
		q.Add("kubernetes_nodes", node)
	}

	if in.TimeStart != nil {
		q.Set("time_start", in.TimeStart.Format(time.RFC3339Nano))
	}

	if in.TimeEnd != nil {
		q.Set("time_end", in.TimeEnd.Format(time.RFC3339Nano))
	}

	addCursorPageArgs(q, in.PageArgs)

	var endpoint string
	if in.ProjectID != nil {
		endpoint = "/api/v2/projects/" + url.PathEscape(*in.ProjectID) + "/events"
		if in.AgentID != nil {
			q.Set("agent_id", *in.AgentID)
		}
	} else {
		endpoint = "/api/v1/agents/" + url.PathEscape(*in.AgentID) + "/events"
	}

	if len(q) != 0 {
		endpoint += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, endpoint, nil)
}

// LegacyEvents uses offset pagination.
// Deprecated: use [Events].
func (c *Client) LegacyEvents(ctx context.Context, params types.LegacyListEvents) (types.Paginator[types.EventV2], error) {
	var out types.Paginator[types.EventV2]

	// Build query parameters
	query := url.Values{}

	if params.Filters != nil {
		if params.Filters.AgentID != nil {
			query.Set("filter.agent_id", *params.Filters.AgentID)
		}
		if params.Filters.Kind != nil {
			query.Set("filter.kind", params.Filters.Kind.String())
		}
		for _, kind := range params.Filters.Kinds {
			query.Add("filter.kinds", kind.String())
		}
		for _, name := range params.Filters.MetadataNames {
			query.Add("filter.metadata.name", name)
		}
		// Kubernetes context filters
		if params.Filters.Cluster != nil {
			query.Set("filter.cluster", *params.Filters.Cluster)
		}
		if params.Filters.Namespace != nil {
			query.Set("filter.namespace", *params.Filters.Namespace)
		}
		if params.Filters.Node != nil {
			query.Set("filter.node", *params.Filters.Node)
		}
		if params.Filters.TimeStart != nil {
			query.Set("filter.time_start", params.Filters.TimeStart.Format(time.RFC3339Nano))
		}
		if params.Filters.TimeEnd != nil {
			query.Set("filter.time_end", params.Filters.TimeEnd.Format(time.RFC3339Nano))
		}
	}

	// Add pagination parameters
	if params.PageArgs.Page != nil {
		query.Set("page", strconv.Itoa(*params.PageArgs.Page))
	}
	if params.PageArgs.PerPage != nil {
		query.Set("perPage", strconv.Itoa(*params.PageArgs.PerPage))
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

// BlockEvent blocks an event by creating a network policy rule in the specified scope.
func (c *Client) BlockEvent(ctx context.Context, scope types.NetworkPolicyScope, eventID string, reason string) (types.EventActionPerformed, error) {
	var out types.EventActionPerformed

	action := types.EventAction{
		ActionType: types.EventActionTypeBlock,
		Scope:      scope,
		Reason:     reason,
	}

	url := "/api/v1/events/" + eventID + "/actions/block"
	return out, c.do(ctx, &out, http.MethodPost, url, action)
}
