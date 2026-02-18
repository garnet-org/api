package spec

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
	"github.com/getkin/kin-openapi/openapi3"
)

func TestAshkaalProfileSchemaValidation(t *testing.T) {
	schema := loadAshkaalProfileSchema(t)

	tests := []struct {
		name    string
		profile ongoing.Profile
	}{
		{
			name:    "full_profile",
			profile: buildFullProfile(),
		},
		{
			name:    "zero_profile",
			profile: ongoing.Profile{},
		},
		{
			name: "network_only",
			profile: ongoing.Profile{
				Network: ongoing.NetProfile{
					Egress: ongoing.Direction{
						Domains: []string{"example.com"},
					},
				},
			},
		},
		{
			name: "assertions_with_null_entry",
			profile: ongoing.Profile{
				Assertions: []ongoing.Assertion{{}},
			},
		},
		{
			name: "base_scenarios_only",
			profile: ongoing.Profile{
				Base: ongoing.Base{
					Scenarios: ongoing.Scenarios{
						GitHub: ongoing.ScenarioGitHub{
							ScenarioType: ongoing.ScenarioTypeGitHub,
							Repository:   "acme/payment-service",
							RunID:        "run_123",
							Job:          "deploy",
						},
					},
				},
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			payload, err := json.Marshal(testCase.profile)
			assert.NoError(t, err)

			var document any
			assert.NoError(t, json.Unmarshal(payload, &document))
			assert.NoError(t, schema.VisitJSON(document))
		})
	}
}

func loadAshkaalProfileSchema(t *testing.T) *openapi3.Schema {
	t.Helper()

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	path := filepath.Join("ashkaal.yaml")
	doc, err := loader.LoadFromFile(path)
	assert.NoError(t, err)
	assert.NoError(t, doc.Validate(context.Background()))

	schemaRef, ok := doc.Components.Schemas["AshkaalProfile"]
	assert.True(t, ok)
	assert.NotZero(t, schemaRef)
	assert.NotZero(t, schemaRef.Value)
	return schemaRef.Value
}

func buildFullProfile() ongoing.Profile {
	now := time.Date(2026, 2, 17, 12, 30, 0, 0, time.UTC)

	return ongoing.Profile{
		Base: ongoing.Base{
			UUID:      "det-001",
			Timestamp: now.Format(time.RFC3339),
			Note:      "Outbound connection to new domain",
			Metadata: ongoing.Metadata{
				Kind:         "profile",
				Name:         "egress-profile",
				Format:       "json",
				Version:      "1.0",
				Description:  "Profile for outbound traffic",
				Tactic:       "command-and-control",
				Technique:    "T1071",
				SubTechnique: "T1071.001",
				Importance:   "high",
			},
			Attenuator: ongoing.Attenuator{
				AttenuatedBy:     "garnet-attenuator",
				Interpretation:   "Known update service",
				IsFalsePositive:  false,
				NewSeverity:      40,
				NewSeverityLevel: "medium",
				NewConfidence:    0.65,
				NewRiskScore:     35.2,
			},
			Score: ongoing.Score{
				Source:        "rule:egress-profile",
				Severity:      72,
				SeverityLevel: "high",
				Confidence:    0.84,
				RiskScore:     60.3,
				Reasons:       []string{"new domain", "suspicious port"},
			},
			Background: ongoing.Background{
				Files: ongoing.FileAggregate{
					Root: ongoing.FSDir{
						Path: "/srv/app",
						Base: "app",
						Files: []ongoing.FSFile{
							{
								Path:    "/srv/app/config.yaml",
								Base:    "config.yaml",
								Actions: []string{"open", "read"},
								Mode:    "0644",
								Owner:   ongoing.FileOwner{UID: 1000, GID: 1000},
								Metadata: ongoing.FileMetadata{
									Size:   2048,
									Access: now.Format(time.RFC3339),
								},
							},
						},
					},
				},
				Flows: ongoing.FlowAggregate{
					IPVersion: 4,
					Protocols: []ongoing.ProtocolAggregate{
						{
							Proto: "tcp",
							Pairs: []ongoing.ProtocolLocalRemoteAgg{
								{
									Nodes: ongoing.LocalRemotePair{
										Local:  ongoing.ProtocolNode{Address: "10.0.0.5", Name: "build-agent"},
										Remote: ongoing.ProtocolNode{Address: "93.184.216.34", Name: "example.com"},
									},
									PortMatrix: []ongoing.PortCommAgg{
										{
											SrcPort: 50432,
											DstPort: 443,
											Phase: ongoing.Phase{
												Direction:  "egress",
												InitatedBy: "local",
												Status:     "completed",
												EndedBy:    "remote",
											},
										},
									},
								},
							},
						},
					},
				},
				Ancestry: []ongoing.Process{
					{
						Start: "2026-02-17T12:00:00Z",
						Exit:  "2026-02-17T12:05:00Z",
						Code:  0,
						UID:   1000,
						Pid:   4321,
						Ppid:  4210,
						Comm:  "runner",
						Cmd:   "/usr/bin/runner --once",
						Exe:   "/usr/bin/runner",
					},
				},
			},
			Scenarios: ongoing.Scenarios{
				GitHub: ongoing.ScenarioGitHub{
					ScenarioType: ongoing.ScenarioTypeGitHub,
					Repository:   "acme/payment-service",
					Job:          "deploy",
					RunNumber:    "42",
					RunID:        "run_123",
					ServerURL:    "https://github.com",
					CreatedAt:    now,
					UpdateAt:     now,
				},
				HostOS: ongoing.ScenarioHostOS{
					ScenarioType: ongoing.ScenarioTypeHostOS,
					MachineID:    "machine-001",
					Hostname:     "runner-host",
					IP:           "10.0.0.5",
					OS:           "linux",
					Arch:         "amd64",
				},
				K8S: ongoing.ScenarioK8S{
					ScenarioType: ongoing.ScenarioTypeK8S,
					Cluster:      "prod-cluster",
					Namespace:    "ci",
					Pod:          "runner-0",
					Node:         "node-a",
				},
			},
		},
		Network: ongoing.NetProfile{
			Egress: ongoing.Direction{
				Peers: []ongoing.Peer{
					{
						Protocol:      "tcp",
						LocalAddress:  "10.0.0.5",
						RemoteAddress: "93.184.216.34",
						RemoteNames:   []string{"example.com"},
						RemotePorts:   []string{"443"},
						Detections:    []string{"outbound-domain-allowlist"},
						ProcTrees: []ongoing.ProcessTree{
							{Ancestry: []string{"bash", "curl"}},
						},
					},
				},
				Domains: []string{"example.com"},
			},
		},
		Telemetry: ongoing.Telemetry{
			Network: ongoing.NetTelemetry{
				Egress: ongoing.DirectionNetTelemetry{
					TotalDomains:     5,
					TotalConnections: 20,
				},
				Ingress: ongoing.DirectionNetTelemetry{
					TotalDomains:     8,
					TotalConnections: 10,
				},
				Local: ongoing.DirectionNetTelemetry{
					TotalDomains:     3,
					TotalConnections: 15,
				},
			},
		},
		Assertions: []ongoing.Assertion{
			{
				Result: ongoing.AssertionResultBad,
				Evidence: []ongoing.Evidence{
					{
						Timestamp: "2026-02-17T12:10:00Z",
						EventName: "network_peer",
						Peer: ongoing.Peer{
							Protocol:      "tcp",
							RemoteAddress: "93.184.216.34",
							RemoteNames:   []string{"example.com"},
							RemotePorts:   []string{"443"},
							Detections:    []string{"outbound-domain-allowlist"},
							ProcTrees: []ongoing.ProcessTree{
								{Ancestry: []string{"bash", "curl"}},
							},
						},
					},
				},
			},
		},
	}
}
