package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/garnet-org/api/types"
)

// CreateNetworkPolicy creates a new network policy.
func (c *Client) CreateNetworkPolicy(ctx context.Context, policy types.CreateNetworkPolicy) (types.NetworkPolicyCreated, error) {
	var out types.NetworkPolicyCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/network_policies", policy)
}

// NetworkPolicy retrieves a network policy by ID.
func (c *Client) NetworkPolicy(ctx context.Context, policyID string) (types.NetworkPolicy, error) {
	var out types.NetworkPolicy

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/network_policies/"+policyID, nil)
}

// UpdateNetworkPolicy updates an existing network policy.
func (c *Client) UpdateNetworkPolicy(ctx context.Context, policyID string, policy types.UpdateNetworkPolicy) (types.NetworkPolicyUpdated, error) {
	var out types.NetworkPolicyUpdated

	return out, c.do(ctx, &out, http.MethodPatch, "/api/v1/network_policies/"+policyID, policy)
}

// DeleteNetworkPolicy deletes a network policy.
func (c *Client) DeleteNetworkPolicy(ctx context.Context, policyID string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/network_policies/"+policyID, nil)
}

// NetworkPolicies lists network policies by scope.
func (c *Client) NetworkPolicies(ctx context.Context, scope types.NetworkPolicyScope) ([]types.NetworkPolicy, error) {
	var out []types.NetworkPolicy

	// Make the API call
	path := "/api/v1/network_policies/scope/" + string(scope)
	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}

// MergedNetworkPolicy retrieves a merged network policy for a specific context.
func (c *Client) MergedNetworkPolicy(ctx context.Context, repositoryID, workflowName string) (types.MergedNetworkPolicy, error) {
	var out types.MergedNetworkPolicy

	q := url.Values{}
	if repositoryID != "" {
		q.Set("repository_id", repositoryID)
	}
	if workflowName != "" {
		q.Set("workflow_name", workflowName)
	}

	path := "/api/v1/network_policies/merged"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}

// MergedNetworkPolicyJibrilFormat retrieves a merged network policy in Jibril-compatible format.
func (c *Client) MergedNetworkPolicyJibrilFormat(ctx context.Context, repositoryID, workflowName string) (map[string]interface{}, error) {
	var out map[string]interface{}

	q := url.Values{}
	if repositoryID != "" {
		q.Set("repository_id", repositoryID)
	}
	if workflowName != "" {
		q.Set("workflow_name", workflowName)
	}
	q.Set("format", "jibril")

	path := "/api/v1/network_policies/merged"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}

// CreateNetworkPolicyRule creates a new rule for a network policy.
func (c *Client) CreateNetworkPolicyRule(ctx context.Context, policyID string, rule types.CreateNetworkPolicyRule) (types.NetworkPolicyRuleCreated, error) {
	var out types.NetworkPolicyRuleCreated

	return out, c.do(ctx, &out, http.MethodPost, "/api/v1/network_policies/"+policyID+"/rules", rule)
}

// NetworkPolicyRule retrieves a network policy rule by ID.
func (c *Client) NetworkPolicyRule(ctx context.Context, ruleID string) (types.NetworkPolicyRule, error) {
	var out types.NetworkPolicyRule

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/network_policy_rules/"+ruleID, nil)
}

// UpdateNetworkPolicyRule updates an existing network policy rule.
func (c *Client) UpdateNetworkPolicyRule(ctx context.Context, ruleID string, rule types.UpdateNetworkPolicyRule) (types.NetworkPolicyRuleUpdated, error) {
	var out types.NetworkPolicyRuleUpdated

	return out, c.do(ctx, &out, http.MethodPatch, "/api/v1/network_policy_rules/"+ruleID, rule)
}

// DeleteNetworkPolicyRule deletes a network policy rule.
func (c *Client) DeleteNetworkPolicyRule(ctx context.Context, ruleID string) error {
	return c.do(ctx, nil, http.MethodDelete, "/api/v1/network_policy_rules/"+ruleID, nil)
}

// ClusterNetworkPolicy retrieves a network policy for a specific Kubernetes cluster.
func (c *Client) ClusterNetworkPolicy(ctx context.Context, clusterName string) (types.ClusterNetworkPolicy, error) {
	var out types.ClusterNetworkPolicy

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/network_policies/k8s/cluster/"+clusterName, nil)
}

// NodeNetworkPolicy retrieves a network policy for a specific Kubernetes node.
func (c *Client) NodeNetworkPolicy(ctx context.Context, clusterName, nodeName string) (types.NodeNetworkPolicy, error) {
	var out types.NodeNetworkPolicy

	return out, c.do(ctx, &out, http.MethodGet, "/api/v1/network_policies/k8s/cluster/"+clusterName+"/node/"+nodeName, nil)
}

// MergedNetworkPolicyForK8s retrieves a merged network policy for a Kubernetes context.
func (c *Client) MergedNetworkPolicyForK8s(ctx context.Context, clusterName, nodeName string) (types.MergedNetworkPolicy, error) {
	var out types.MergedNetworkPolicy

	q := url.Values{}
	if clusterName != "" {
		q.Set("cluster_name", clusterName)
	}
	if nodeName != "" {
		q.Set("node_name", nodeName)
	}

	path := "/api/v1/network_policies/k8s/merged"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}

// MergedNetworkPolicyForK8sJibrilFormat retrieves a merged network policy for a Kubernetes context in Jibril-compatible format.
func (c *Client) MergedNetworkPolicyForK8sJibrilFormat(ctx context.Context, clusterName, nodeName string) (map[string]interface{}, error) {
	var out map[string]interface{}

	q := url.Values{}
	if clusterName != "" {
		q.Set("cluster_name", clusterName)
	}
	if nodeName != "" {
		q.Set("node_name", nodeName)
	}
	q.Set("format", "jibril")

	path := "/api/v1/network_policies/k8s/merged"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}

	return out, c.do(ctx, &out, http.MethodGet, path, nil)
}
