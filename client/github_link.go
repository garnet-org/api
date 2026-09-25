package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/garnet-org/api/types"
)

// ProjectGitHubLinks lists the GitHub owners and repositories claimed by a project.
func (c *Client) ProjectGitHubLinks(ctx context.Context, projectID string) ([]types.ProjectGitHubLink, error) {
	var out []types.ProjectGitHubLink

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/projects/"+url.PathEscape(projectID)+"/github/links", nil)
}
