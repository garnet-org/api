package types

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/garnet-org/api/validator"
)

type PRReviewInput struct {
	GitHubOrg  string `json:"githubOrg"`
	Repo       string `json:"repo"`
	PullNumber *int   `json:"pullNumber,omitempty"`
	HeadSHA    string `json:"headSha,omitempty"`
}

func (in *PRReviewInput) Validate() error {
	v := validator.New()
	in.GitHubOrg = strings.TrimSpace(in.GitHubOrg)
	in.Repo = strings.TrimSpace(in.Repo)
	if !regexp.MustCompile(`^[A-Za-z0-9-]+$`).MatchString(in.GitHubOrg) {
		v.Add("githubOrg", "invalid github organization")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(in.Repo) || in.Repo == "." || in.Repo == ".." {
		v.Add("repo", "invalid repository")
	}
	if (in.PullNumber != nil) == (in.HeadSHA != "") {
		v.Add("pullNumber", "exactly one of pullNumber or headSha is required")
	}
	if in.PullNumber != nil && *in.PullNumber <= 0 {
		v.Add("pullNumber", "must be positive")
	}
	if in.HeadSHA != "" && !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(in.HeadSHA) {
		v.Add("headSha", "invalid commit SHA")
	}
	return v.AsError()
}

type PRReview struct {
	Result         string              `json:"result"`
	CaptureQuality string              `json:"capture_quality"`
	Status         RuntimeReviewStatus `json:"status"`
	Scope          string              `json:"scope"`
	HeadSHA        string              `json:"head_sha"`
	MarkerCommit   string              `json:"marker_commit"`
	BoundToHead    bool                `json:"bound_to_head"`
	Reasons        []string            `json:"reasons"`
	CommentURL     string              `json:"comment_url"`
	Envelope       json.RawMessage     `json:"envelope,omitempty"`
	ProfileIDs     []string            `json:"profile_ids,omitempty"`
}

type RuntimeReviewStatus string

const (
	RuntimeReviewStatusFinalized   RuntimeReviewStatus = "finalized"
	RuntimeReviewStatusMissing     RuntimeReviewStatus = "missing"
	RuntimeReviewStatusMalformed   RuntimeReviewStatus = "malformed"
	RuntimeReviewStatusStale       RuntimeReviewStatus = "stale"
	RuntimeReviewStatusRecording   RuntimeReviewStatus = "recording"
	RuntimeReviewStatusIncomplete  RuntimeReviewStatus = "incomplete"
	RuntimeReviewStatusUnsupported RuntimeReviewStatus = "unsupported"
)
