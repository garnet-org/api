package client

import (
	"context"
	"maps"
	"net/http"
	"net/url"
	"strconv"

	"github.com/garnet-org/api/types"
)

// CreateAgent creates a new agent with the provided data.
func (c *Client) CreateAgent(ctx context.Context, agent types.CreateAgent) (types.AgentCreated, error) {
	var out types.AgentCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/agents", agent)
}

// Agent retrieves an agent by its ID.
func (c *Client) Agent(ctx context.Context, agentID string) (types.Agent, error) {
	var out types.Agent

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/agents/"+agentID, nil)
}

// DeleteAgent deletes an agent with the provided ID.
func (c *Client) DeleteAgent(ctx context.Context, agentID string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/agents/"+agentID, nil)
}

// UpdateAgent updates an existing agent with the provided ID and data.
func (c *Client) UpdateAgent(ctx context.Context, agentID string, agent types.UpdateAgent) error {
	return c.do(ctx, nil, http.MethodPatch, "/api/v1/agents/"+agentID, agent)
}

// Agents retrieves a list of agents with optional filters and pagination.
func (c *Client) Agents(ctx context.Context, in types.ListAgents) (types.Page[types.Agent], error) {
	var out types.Page[types.Agent]

	q := url.Values{}
	q1 := in.Filters.Encode()
	q2 := in.Labels.Encode()

	maps.Copy(q, q1)
	maps.Copy(q, q2)

	// Add pagination parameters
	if in.First != nil {
		q.Set("first", strconv.FormatUint(uint64(*in.First), 10))
	}
	if in.Last != nil {
		q.Set("last", strconv.FormatUint(uint64(*in.Last), 10))
	}
	if in.After != nil {
		q.Set("after", string(*in.After))
	}
	if in.Before != nil {
		q.Set("before", string(*in.Before))
	}

	path := "/api/v1/agents?" + q.Encode()

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}
