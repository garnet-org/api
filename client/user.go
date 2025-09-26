package client

import (
	"context"
	"net/http"

	"github.com/garnet-org/api/types"
)

// CurrentUser retrieves information about the currently authenticated user.
func (c *Client) CurrentUser(ctx context.Context) (*types.CurrentUserInfo, error) {
	var userInfo types.CurrentUserInfo
	if err := c.do(ctx, &userInfo, http.MethodGet, "/api/v1/me", nil); err != nil {
		return nil, err
	}
	return &userInfo, nil
}