package client

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/garnet-org/api/types"
)

// CreateAgent creates a new agent with the provided data.
func (c *Client) CreateAgent(ctx context.Context, agent types.CreateAgent) (types.AgentCreated, error) {
	var out types.AgentCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/agents", agent)
}

func (c *Client) Agents(ctx context.Context, in types.ListAgents) (types.CursorPage[types.Agent], error) {
	var out types.CursorPage[types.Agent]

	q := url.Values{}

	if in.Active != nil {
		q.Set("active", strconv.FormatBool(*in.Active))
	}

	if in.OS != nil {
		q.Set("os", *in.OS)
	}

	if in.Arch != nil {
		q.Set("arch", *in.Arch)
	}

	if in.Hostname != nil {
		q.Set("hostname", *in.Hostname)
	}

	if in.Version != nil {
		q.Set("version", *in.Version)
	}

	if in.IP != nil {
		q.Set("ip", *in.IP)
	}

	if in.MachineID != nil {
		q.Set("machine_id", *in.MachineID)
	}

	for _, kind := range in.Kinds {
		q.Add("kinds", string(kind))
	}

	for key, value := range in.Labels {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		q.Set("label."+key, value)
	}

	if in.TimeStart != nil {
		q.Set("time_start", in.TimeStart.Format(time.RFC3339Nano))
	}

	if in.TimeEnd != nil {
		q.Set("time_end", in.TimeEnd.Format(time.RFC3339Nano))
	}

	addCursorPageArgs(q, in.PageArgs)

	path := "/api/v2/projects/" + url.PathEscape(in.ProjectID) + "/agents"
	if len(q) != 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
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

// LegacyAgents retrieves a list of agents with optional filters and pagination.
func (c *Client) LegacyAgents(ctx context.Context, in types.LegacyListAgents) (types.Paginator[types.Agent], error) {
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

func (c *Client) AgentsCounts(ctx context.Context, in types.RetrieveAgentsCounts) (types.AgentsCounts, error) {
	var out types.AgentsCounts

	if in.ProjectID == "" {
		return out, errors.New("projectID is required")
	}

	q := url.Values{}
	if in.Kind != nil {
		q.Set("kind", string(*in.Kind))
	}
	if in.CreatedSince != nil {
		q.Set("createdSince", in.CreatedSince.Format(time.RFC3339Nano))
	}

	path := "/api/v1/projects/" + url.PathEscape(in.ProjectID) + "/agents_counts"
	if len(q) != 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}
