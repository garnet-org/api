package types //nolint:revive // Package name is intentionally descriptive

import (
	"encoding/json"
	"time"

	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
)

// MCP (Model Context Protocol) types.

// MCP Tool Names.
const (
	McpToolListEvents          = "garnetListEvents"
	McpToolGetEvent            = "garnetGetEvent"
	McpToolBlockEvent          = "garnetBlockEvent"
	McpToolListAgents          = "garnetListAgents"
	McpToolListIssues          = "garnetListIssues"
	McpToolGetIssue            = "garnetGetIssue"
	McpToolBlockIssue          = "garnetBlockIssue"
	McpToolListNetworkPolicies = "garnetListNetworkPolicies"
)

// MCP Default Values.
const (
	McpDefaultTimeframe = "24h"
	McpDefaultScope     = "workflow"
)

// MCPInitializeParams represents the initialization request parameters.
type MCPInitializeParams struct {
	ClientInfo MCPClientInfo `json:"clientInfo"`
}

// MCPClientInfo contains information about the MCP client.
type MCPClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCPInitializeResult represents the initialization response.
type MCPInitializeResult struct {
	ServerInfo   MCPServerInfo   `json:"serverInfo"`
	Capabilities MCPCapabilities `json:"capabilities"`
}

// MCPServerInfo contains information about the MCP server.
type MCPServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCPCapabilities describes the server's capabilities.
type MCPCapabilities struct {
	Tools *MCPToolsCapability `json:"tools,omitempty"`
}

// MCPToolsCapability indicates tool support.
type MCPToolsCapability struct{}

// McpToolDefinition represents a tool definition.
type McpToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// McpToolCallParams represents tool invocation parameters.
type McpToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// McpToolCallResult represents the result of a tool call.
type McpToolCallResult struct {
	Content []McpContent `json:"content"`
}

// McpContent represents content in a tool response.
type McpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// McpToolError represents an error response from a tool.
type McpToolError struct {
	IsError bool         `json:"isError"`
	Content []McpContent `json:"content"`
}

// McpEventSummary represents a summarized event for MCP responses.
type McpEventSummary struct {
	ID        string       `json:"id"`
	Kind      string       `json:"kind"`
	CreatedAt string       `json:"created_at"`
	Agent     Agent        `json:"agent"`
	Data      ongoing.Base `json:"data"`
}

// McpListEventsResult represents the response for list_events.
type McpListEventsResult struct {
	Total     int               `json:"total"`
	Timeframe string            `json:"timeframe"`
	Events    []McpEventSummary `json:"events"`
}

// McpIssueSummary represents a summarized issue for list responses.
type McpIssueSummary struct {
	ID               string        `json:"id"`
	Class            IssueClass    `json:"class"`
	Description      string        `json:"description"`
	State            IssueState    `json:"state"`
	Priority         IssuePriority `json:"priority"`
	Labels           IssueLabels   `json:"labels"`
	Ignored          bool          `json:"ignored"`
	CreatedAt        string        `json:"created_at"`
	UpdatedAt        string        `json:"updated_at"`
	EventCount       int           `json:"event_count"`
	IgnoredReason    string        `json:"ignored_reason,omitempty"`
	IgnoredBy        string        `json:"ignored_by,omitempty"`
	IgnoredAt        string        `json:"ignored_at,omitempty"`
	NetworkPolicyID  string        `json:"network_policy_id,omitempty"`
}

// McpListIssuesResult represents the response for list_issues.
type McpListIssuesResult struct {
	Total  int               `json:"total"`
	Issues []McpIssueSummary `json:"issues"`
}

// McpIssueDetail represents detailed issue information.
type McpIssueDetail struct {
	ID                  string             `json:"id"`
	Class               IssueClass         `json:"class"`
	Description         string             `json:"description"`
	State               IssueState         `json:"state"`
	Priority            IssuePriority      `json:"priority"`
	Labels              IssueLabels        `json:"labels"`
	Ignored             bool               `json:"ignored"`
	CreatedAt           string             `json:"created_at"`
	UpdatedAt           string             `json:"updated_at"`
	IgnoredReason       string             `json:"ignored_reason,omitempty"`
	IgnoredBy           string             `json:"ignored_by,omitempty"`
	IgnoredAt           string             `json:"ignored_at,omitempty"`
	PolicyScope         *NetworkPolicyScope `json:"policy_scope,omitempty"`
	NetworkPolicyID     string             `json:"network_policy_id,omitempty"`
	NetworkPolicyRuleID string             `json:"network_policy_rule_id,omitempty"`
	Events              []McpEventSummary  `json:"events"`
}

// McpBlockIssueResult represents the response for block_issue.
type McpBlockIssueResult struct {
	ID                string                  `json:"id"`
	State             IssueState              `json:"state"`
	NetworkPolicyID   string                  `json:"network_policy_id"`
	NetworkPolicyRule McpNetworkPolicyRuleRef `json:"network_policy_rule"`
	UpdatedAt         string                  `json:"updated_at"`
}

// McpNetworkPolicyRuleRef represents a reference to a network policy rule.
type McpNetworkPolicyRuleRef struct {
	Type  NetworkPolicyRuleType `json:"type"`
	Value string                `json:"value"`
}

// McpNetworkPolicySummary represents a network policy in list responses.
type McpNetworkPolicySummary struct {
	ID        string                 `json:"id"`
	Scope     NetworkPolicyScope     `json:"scope"`
	Config    NetworkPolicyConfig    `json:"config"`
	CreatedAt string                 `json:"created_at"`
	UpdatedAt string                 `json:"updated_at"`
	Rules     []McpNetworkPolicyRule `json:"rules,omitempty"`
}

// McpNetworkPolicyRule represents a network policy rule in MCP responses.
type McpNetworkPolicyRule struct {
	ID        string                `json:"id"`
	Type      NetworkPolicyRuleType `json:"type"`
	Value     string                `json:"value"`
	Action    NetworkPolicyType     `json:"action"`
	CreatedAt string                `json:"created_at"`
}

// McpListNetworkPoliciesResult represents the response for list_network_policies.
type McpListNetworkPoliciesResult struct {
	Total    int                       `json:"total"`
	Policies []McpNetworkPolicySummary `json:"policies"`
}

// NewMcpToolResult creates a standard MCP tool result.
func NewMcpToolResult(text string) McpToolCallResult {
	return McpToolCallResult{
		Content: []McpContent{
			{
				Type: "text",
				Text: text,
			},
		},
	}
}

// NewMcpToolError creates an MCP tool error response.
func NewMcpToolError(message string) McpToolError {
	return McpToolError{
		IsError: true,
		Content: []McpContent{
			{
				Type: "text",
				Text: message,
			},
		},
	}
}

// NewMcpEventSummary converts an Event to McpEventSummary.
func NewMcpEventSummary(event Event) McpEventSummary {
	return McpEventSummary{
		ID:        event.ID,
		Kind:      string(event.Kind),
		CreatedAt: event.CreatedAt.Format(time.RFC3339),
		Agent:     event.Agent,
		Data:      event.Data,
	}
}

// NewMcpEventSummaryFromV2 converts an EventV2 to McpEventSummary.
func NewMcpEventSummaryFromV2(event EventV2) McpEventSummary {
	return McpEventSummary{
		ID:        event.ID,
		Kind:      string(event.Kind),
		CreatedAt: event.CreatedAt.Format(time.RFC3339),
		Agent:     event.Agent,
		Data:      event.Data,
	}
}

// NewMcpIssueSummary converts an Issue to McpIssueSummary.
func NewMcpIssueSummary(issue Issue) McpIssueSummary {
	summary := McpIssueSummary{
		ID:          issue.ID,
		Class:       issue.Class,
		Description: issue.Description,
		State:       issue.State,
		Priority:    issue.Priority,
		Labels:      issue.Labels,
		Ignored:     issue.Ignored,
		CreatedAt:   issue.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   issue.UpdatedAt.Format(time.RFC3339),
		EventCount:  len(issue.Events),
	}

	if issue.Ignored {
		summary.IgnoredReason = issue.IgnoredReason
		summary.IgnoredBy = issue.IgnoredBy
		if issue.IgnoredAt != nil {
			summary.IgnoredAt = issue.IgnoredAt.Format(time.RFC3339)
		}
	}

	if issue.NetworkPolicyID != nil {
		summary.NetworkPolicyID = *issue.NetworkPolicyID
	}

	return summary
}

// NewMcpIssueDetail converts an Issue to McpIssueDetail.
func NewMcpIssueDetail(issue Issue) McpIssueDetail {
	detail := McpIssueDetail{
		ID:          issue.ID,
		Class:       issue.Class,
		Description: issue.Description,
		State:       issue.State,
		Priority:    issue.Priority,
		Labels:      issue.Labels,
		Ignored:     issue.Ignored,
		CreatedAt:   issue.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   issue.UpdatedAt.Format(time.RFC3339),
		Events:      make([]McpEventSummary, 0, len(issue.Events)),
	}

	if issue.Ignored {
		detail.IgnoredReason = issue.IgnoredReason
		detail.IgnoredBy = issue.IgnoredBy
		if issue.IgnoredAt != nil {
			detail.IgnoredAt = issue.IgnoredAt.Format(time.RFC3339)
		}
	}

	if issue.PolicyScope != nil {
		detail.PolicyScope = issue.PolicyScope
	}

	if issue.NetworkPolicyID != nil {
		detail.NetworkPolicyID = *issue.NetworkPolicyID
	}

	if issue.NetworkPolicyRuleID != nil {
		detail.NetworkPolicyRuleID = *issue.NetworkPolicyRuleID
	}

	// Convert events
	for _, event := range issue.Events {
		detail.Events = append(detail.Events, NewMcpEventSummary(event))
	}

	return detail
}

// NewMcpNetworkPolicySummary converts a NetworkPolicy to McpNetworkPolicySummary.
func NewMcpNetworkPolicySummary(policy NetworkPolicy, includeRules bool) McpNetworkPolicySummary {
	summary := McpNetworkPolicySummary{
		ID:        policy.ID,
		Scope:     policy.Scope,
		Config:    policy.Config,
		CreatedAt: policy.CreatedAt.Format(time.RFC3339),
		UpdatedAt: policy.UpdatedAt.Format(time.RFC3339),
	}

	if includeRules && policy.Rules != nil {
		summary.Rules = make([]McpNetworkPolicyRule, 0, len(policy.Rules))
		for _, rule := range policy.Rules {
			summary.Rules = append(summary.Rules, McpNetworkPolicyRule{
				ID:        rule.ID,
				Type:      rule.Type,
				Value:     rule.Value,
				Action:    rule.Action,
				CreatedAt: rule.CreatedAt.Format(time.RFC3339),
			})
		}
	}

	return summary
}