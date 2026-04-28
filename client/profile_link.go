package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/garnet-org/api/types"
)

func (c *Client) CreateProfileLink(ctx context.Context, profileID string, in types.CreateProfileLink) (types.CreatedProfileLink, error) {
	var out types.CreatedProfileLink

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/profiles/"+profileID+"/links", in)
}

func (c *Client) ProfileLinks(ctx context.Context, in types.ListProfileLinks) (types.Paginator[types.ProfileLink], error) {
	var out types.Paginator[types.ProfileLink]

	q := url.Values{}
	if in.Page != nil {
		q.Set("page", strconv.Itoa(*in.Page))
	}
	if in.PerPage != nil {
		q.Set("perPage", strconv.Itoa(*in.PerPage))
	}

	path := "/api/v1/profiles/" + in.ProfileID + "/links"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}

func (c *Client) ProfileLink(ctx context.Context, linkID string) (types.ProfileLink, error) {
	var out types.ProfileLink

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/profile_links/"+linkID, nil)
}

func (c *Client) UpdateProfileLink(ctx context.Context, linkID string, in types.UpdateProfileLink) (types.ProfileLink, error) {
	var out types.ProfileLink

	return out, c.do(ctx, &out, http.MethodPatch, "/api/v1/profile_links/"+linkID, in)
}

func (c *Client) DeleteProfileLink(ctx context.Context, linkID string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/profile_links/"+linkID, nil)
}

func (c *Client) PublicProfile(ctx context.Context, token string) (types.Profile, error) {
	var out types.Profile

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/public_profiles/"+token, nil)
}
