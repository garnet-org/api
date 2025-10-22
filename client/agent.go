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

// AgentHeartbeat sends a heartbeat to update the agent's last_seen timestamp.
// The agent ID is extracted from the agent token.
func (c *Client) AgentHeartbeat(ctx context.Context) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/agent_heartbeat", nil)
}

// Agents retrieves a list of agents with optional filters and pagination.
func (c *Client) Agents(ctx context.Context, in types.ListAgents) (types.Paginator[types.Agent], error) {
	var out types.Paginator[types.Agent]

	q := url.Values{}
	q1 := in.Filters.Encode()
	q2 := in.Labels.Encode()

	maps.Copy(q, q1)
	maps.Copy(q, q2)

	// Add pagination parameters
	if in.Page != nil {
		q.Set("page", strconv.Itoa(*in.Page))
	}
	if in.PerPage != nil {
		q.Set("perPage", strconv.Itoa(*in.PerPage))
	}

	path := "/api/v1/agents?" + q.Encode()

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}
