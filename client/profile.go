package client

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/garnet-org/api/types"
	"github.com/garnet-org/api/types/errs"
)

func (c *Client) CreateProfile(ctx context.Context, in types.CreateProfile) (types.CreatedProfile, error) {
	var out types.CreatedProfile
	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/profiles", in)
}

func (c *Client) Profiles(ctx context.Context, in types.ListProfiles) (types.CursorPage[types.Profile], error) {
	var out types.CursorPage[types.Profile]

	var path string
	if in.ProjectID != nil {
		path = "/api/v1/projects/" + *in.ProjectID + "/profiles"
	} else if in.AgentID != nil {
		path = "/api/v1/agents/" + *in.AgentID + "/profiles"
	} else {
		return out, errs.InvalidArgumentError("either project_id or agent_id must be provided")
	}

	q := url.Values{}
	if in.TimeStart != nil {
		q.Set("time_start", in.TimeStart.Format(time.RFC3339Nano))
	}
	if in.TimeEnd != nil {
		q.Set("time_end", in.TimeEnd.Format(time.RFC3339Nano))
	}
	addCursorPageArgs(q, in.PageArgs)

	if len(q) != 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}

func (c *Client) Profile(ctx context.Context, runID string) (types.Profile, error) {
	var out types.Profile
	path := "/api/v1/profiles/" + runID
	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}
