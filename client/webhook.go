package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/garnet-org/api/types"
)

// CreateWebhook creates a new webhook.
func (c *Client) CreateWebhook(ctx context.Context, in types.WebhookCreate) (types.WebhookCreated, error) {
	var out types.WebhookCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/webhooks", in)
}

// DeleteWebhook deletes a webhook by its ID.
func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/webhooks/"+id, nil)
}

// ListWebhooks retrieves a list of webhooks.
func (c *Client) ListWebhooks(ctx context.Context, in types.WebhookList) (types.Paginator[types.Webhook], error) {
	var out types.Paginator[types.Webhook]

	q := url.Values{}

	// Add pagination parameters
	if in.Page != nil {
		q.Set("page", strconv.Itoa(*in.Page))
	}
	if in.PerPage != nil {
		q.Set("perPage", strconv.Itoa(*in.PerPage))
	}

	url := "/api/v1/webhooks"
	if len(q) > 0 {
		url += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, url, nil)
}

// UpdateWebhook updates an existing webhook.
func (c *Client) UpdateWebhook(ctx context.Context, id string, in types.WebhookUpdate) (types.WebhookUpdated, error) {
	var out types.WebhookUpdated

	return out, c.do(ctx, &out, http.MethodPatch, "/api/v1/webhooks/"+id, in)
}

// Webhook retrieves a webhook by its ID.
func (c *Client) Webhook(ctx context.Context, id string) (types.Webhook, error) {
	var out types.Webhook

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/webhooks/"+id, nil)
}

// TestWebhook sends a test request to the webhook URL.
func (c *Client) TestWebhook(ctx context.Context, id string) error {
	return c.do(ctx, nil, http.MethodPost, "/api/v1/webhooks/"+id+"/test", nil)
}
