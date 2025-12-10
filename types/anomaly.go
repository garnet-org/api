package types

import "time"

// AnomalyCandidateMessage is published by L1 filter for L2 scorer to process.
type AnomalyCandidateMessage struct {
	EventID    string    `json:"event_id"`
	ProjectID  string    `json:"project_id"`
	AgentID    string    `json:"agent_id"`
	Domain     string    `json:"domain,omitempty"`
	IPAddress  string    `json:"ip_address,omitempty"`
	Port       int       `json:"port,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	ProcessExe string    `json:"process_exe,omitempty"`
	ProcessPID int       `json:"process_pid,omitempty"`
	ProcessCmd string    `json:"process_cmd,omitempty"`
	Cluster    string    `json:"cluster,omitempty"`
	Namespace  string    `json:"namespace,omitempty"`
	Node       string    `json:"node,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// AnomalyToEnrichMessage is published by L2 scorer for L3 enricher to process.
type AnomalyToEnrichMessage struct {
	IssueID   string `json:"issue_id"`
	ProjectID string `json:"project_id"`
}

// AnomalyLabels defines the label keys used for network anomaly issues.
const (
	LabelAnomalyScore           = "anomaly_score"
	LabelAnomalyClassification  = "anomaly_classification"
	LabelAnomalyConfidence      = "anomaly_confidence"
	LabelAnomalyExplanation     = "anomaly_explanation"
	LabelRecommendedAction      = "recommended_action"
	LabelScoreFirstSeen         = "score_first_seen"
	LabelScoreNewProcessPair    = "score_new_process_pair"
	LabelScoreNewProcessIPPair  = "score_new_process_ip_pair"
	LabelScoreHasDetections     = "score_has_detections"
	LabelScoreWorkloadDeviation = "score_workload_deviation"
	LabelScoreFrequencySpike    = "score_frequency_spike"
	LabelEnrichedAt             = "enriched_at"
	LabelReputationSource       = "reputation_source"
)

// AnomalyClassification represents the L3 classification result.
type AnomalyClassification string

// AnomalyClassification values.
const (
	AnomalyClassificationMalicious  AnomalyClassification = "malicious"
	AnomalyClassificationSuspicious AnomalyClassification = "suspicious"
	AnomalyClassificationBenign     AnomalyClassification = "benign"
)

// RecommendedAction represents the L3 recommended action.
type RecommendedAction string

// RecommendedAction values.
const (
	RecommendedActionInvestigate RecommendedAction = "investigate"
	RecommendedActionBlock       RecommendedAction = "block"
	RecommendedActionAllowlist   RecommendedAction = "allowlist"
)

// ScoreToPriority converts an anomaly score (0-1 scale) to an issue priority.
// Thresholds: ≥0.80 Critical, ≥0.60 High, ≥0.40 Medium, <0.40 Low.
func ScoreToPriority(score float64) IssuePriority {
	switch {
	case score >= 0.80:
		return IssuePriorityCritical
	case score >= 0.60:
		return IssuePriorityHigh
	case score >= 0.40:
		return IssuePriorityMedium
	default:
		return IssuePriorityLow
	}
}
