package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/garnet-org/api/types"
)

func (c *Client) CreateDeviceAuthorization(ctx context.Context, in types.CreateDeviceAuthorization) (types.DeviceAuthorizationCreated, error) {
	var out types.DeviceAuthorizationCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/device-authorizations", in)
}

func (c *Client) DeviceAuthorizationStatus(ctx context.Context, deviceCode string) (types.DeviceAuthorizationState, error) {
	var out types.DeviceAuthorizationState

	path := "/api/v1/device-authorizations/" + url.PathEscape(deviceCode)
	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}

func (c *Client) ApproveDeviceAuthorization(ctx context.Context, in types.ApproveDeviceAuthorization) error {
	path := "/api/v1/device-authorizations/" + url.PathEscape(in.DeviceCode) + "/approve"
	return c.do(ctx, nil, http.MethodPost, path, in)
}

func (c *Client) RejectDeviceAuthorization(ctx context.Context, deviceCode string) error {
	path := "/api/v1/device-authorizations/" + url.PathEscape(deviceCode) + "/reject"
	return c.do(ctx, nil, http.MethodPost, path, nil)
}
