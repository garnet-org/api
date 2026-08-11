package client

import (
	"context"
	"net/http"

	"github.com/garnet-org/api/types"
)

// ExchangeGitHubOIDC exchanges a GitHub Actions OIDC ID token for a workflow token.
func (c *Client) ExchangeGitHubOIDC(ctx context.Context, in types.GitHubOIDCExchange) (types.GitHubOIDCExchangeCreated, error) {
	var out types.GitHubOIDCExchangeCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/github/oidc/exchange", in)
}
