package types

import "time"

// FlowBaseline represents a known (domain, IP) baseline for a project scope.
type FlowBaseline struct {
	ID               string    `json:"id"`
	ProjectID        string    `json:"project_id"`
	Domain           string    `json:"domain,omitempty"`
	IPAddress        string    `json:"ip_address,omitempty"`
	Cluster          string    `json:"cluster,omitempty"`
	Namespace        string    `json:"namespace,omitempty"`
	ProcessExe       string    `json:"process_exe,omitempty"` // Process executable for process-domain pair tracking
	FirstSeenAt      time.Time `json:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at"`
	ObservationCount int       `json:"observation_count"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// KnownGoodDomain represents a globally known-good domain.
type KnownGoodDomain struct {
	Domain    string    `json:"domain"`
	Category  string    `json:"category"` // cdn, registry, cloud_service, infrastructure
	CreatedAt time.Time `json:"created_at"`
	Notes     string    `json:"notes,omitempty"`
}
