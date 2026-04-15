package client

import (
	"context"
	"net/url"

	"github.com/garnet-org/api/types"
)

func (c *Client) Billing(ctx context.Context, projectID string) (types.Billing, error) {
	var out types.Billing
	path := "/api/v1/projects/" + url.PathEscape(projectID) + "/billing"
	return out, c.do(ctx, &out, "GET", path, nil)
}

func (c *Client) CreateBillingCheckout(ctx context.Context, projectID string, in types.BillingCheckoutCreate) (types.BillingSession, error) {
	var out types.BillingSession
	path := "/api/v1/projects/" + url.PathEscape(projectID) + "/billing/checkout"
	return out, c.do(ctx, &out, "POST", path, in)
}

func (c *Client) CreateBillingPortal(ctx context.Context, projectID string, in types.BillingPortalCreate) (types.BillingSession, error) {
	var out types.BillingSession
	path := "/api/v1/projects/" + url.PathEscape(projectID) + "/billing/portal"
	return out, c.do(ctx, &out, "POST", path, in)
}
