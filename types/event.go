// Package types contains all the required clients for marshal/unmarshal requests and responses from/to jibril-server.
package types

import (
	"time"

	"github.com/garnet-org/jibril-ashkaal/pkg/kind"
	"github.com/garnet-org/jibril-ashkaal/pkg/ongoing"
	"github.com/garnet-org/api/types/errs"
)

const (
	// ErrInvalidEventKind is returned when the event kind is invalid.
	ErrInvalidEventKind = errs.InvalidArgumentError("invalid event kind")

	// ErrIDcannotBeEmpty is returned when the event ID is empty.
	ErrIDcannotBeEmpty = errs.InvalidArgumentError("id is required")
)

// EventKind represents the type of event.
type EventKind string

const (
	// EventKindDropIP is used for IP drop events.
	EventKindDropIP EventKind = "dropip"

	// EventKindDropDomain is used for domain drop events.
	EventKindDropDomain EventKind = "dropdomain"

	// EventKindFlow is used for network flow events.
	EventKindFlow EventKind = "flow"

	// EventKindCapabilitiesModification indicates a modification of Linux capabilities.
	EventKindCapabilitiesModification EventKind = "capabilities_modification"

	// EventKindCodeModificationThroughProcfs indicates code was modified through /proc filesystem.
	EventKindCodeModificationThroughProcfs EventKind = "code_modification_through_procfs"

	// EventKindCorePatternAccess indicates access to the core pattern configuration.
	EventKindCorePatternAccess EventKind = "core_pattern_access"

	// EventKindCPUFingerprint indicates fingerprinting of CPU characteristics.
	EventKindCPUFingerprint EventKind = "cpu_fingerprint"

	// EventKindCredentialsFilesAccess indicates access to credential-related files.
	EventKindCredentialsFilesAccess EventKind = "credentials_files_access"

	// EventKindFilesystemFingerprint indicates fingerprinting of the filesystem.
	EventKindFilesystemFingerprint EventKind = "filesystem_fingerprint"

	// EventKindJavaDebugLibLoad indicates a Java debug library was loaded.
	EventKindJavaDebugLibLoad EventKind = "java_debug_lib_load"

	// EventKindJavaInstrumentLibLoad indicates a Java instrumentation library was loaded.
	EventKindJavaInstrumentLibLoad EventKind = "java_instrument_lib_load"

	// EventKindMachineFingerprint indicates fingerprinting of the machine.
	EventKindMachineFingerprint EventKind = "machine_fingerprint"

	// EventKindOSFingerprint indicates fingerprinting of the operating system.
	EventKindOSFingerprint EventKind = "os_fingerprint"

	// EventKindOSNetworkFingerprint indicates network-level fingerprinting of the OS.
	EventKindOSNetworkFingerprint EventKind = "os_network_fingerprint"

	// EventKindOSStatusFingerprint indicates OS status-based fingerprinting.
	EventKindOSStatusFingerprint EventKind = "os_status_fingerprint"

	// EventKindPackageRepoConfigModification indicates modification of package repository config.
	EventKindPackageRepoConfigModification EventKind = "package_repo_config_modification"

	// EventKindPAMConfigModification indicates modification of PAM configuration files.
	EventKindPAMConfigModification EventKind = "pam_config_modification"

	// EventKindSchedDebugAccess indicates access to scheduling debug information.
	EventKindSchedDebugAccess EventKind = "sched_debug_access"

	// EventKindShellConfigModification indicates modification of shell configuration files.
	EventKindShellConfigModification EventKind = "shell_config_modification"

	// EventKindSSLCertificateAccess indicates access to SSL certificates.
	EventKindSSLCertificateAccess EventKind = "ssl_certificate_access"

	// EventKindSudoersModification indicates unauthorized modification of sudoers file.
	EventKindSudoersModification EventKind = "sudoers_modification"

	// EventKindSysrqAccess indicates access to SysRq trigger interface.
	EventKindSysrqAccess EventKind = "sysrq_access"

	// EventKindUnprivilegedBPFConfigAccess indicates access to BPF config by an unprivileged user.
	EventKindUnprivilegedBPFConfigAccess EventKind = "unprivileged_bpf_config_access"

	// EventKindGlobalShlibModification indicates global shared library was modified.
	EventKindGlobalShlibModification EventKind = "global_shlib_modification"

	// EventKindEnvironReadFromProcfs indicates environment variables were read from procfs.
	EventKindEnvironReadFromProcfs EventKind = "environ_read_from_procfs"

	// EventKindBinarySelfDeletion indicates a binary deleted itself post-execution.
	EventKindBinarySelfDeletion EventKind = "binary_self_deletion"

	// EventKindCryptoMinerFiles indicates files related to crypto miners were detected.
	EventKindCryptoMinerFiles EventKind = "crypto_miner_files"

	// EventKindAuthLogsTamper indicates tampering with authentication logs.
	EventKindAuthLogsTamper EventKind = "auth_logs_tamper"

	// EventKindBinaryExecutedByLoader indicates a binary was executed by a custom loader.
	EventKindBinaryExecutedByLoader EventKind = "binary_executed_by_loader"

	// EventKindCodeOnTheFly indicates dynamic or just-in-time code execution.
	EventKindCodeOnTheFly EventKind = "code_on_the_fly"

	// EventKindDataEncoderExec indicates execution of a data encoder binary.
	EventKindDataEncoderExec EventKind = "data_encoder_exec"

	// EventKindDenialOfServiceTools indicates use of DoS tools.
	EventKindDenialOfServiceTools EventKind = "denial_of_service_tools"

	// EventKindExecFromUnusualDir indicates execution from an unusual directory.
	EventKindExecFromUnusualDir EventKind = "exec_from_unusual_dir"

	// EventKindFileAttributeChange indicates unauthorized file attribute changes.
	EventKindFileAttributeChange EventKind = "file_attribute_change"

	// EventKindHiddenELFExec indicates execution of a hidden ELF binary.
	EventKindHiddenELFExec EventKind = "hidden_elf_exec"

	// EventKindInterpreterShellSpawn indicates spawning of a shell through an interpreter.
	EventKindInterpreterShellSpawn EventKind = "interpreter_shell_spawn"

	// EventKindNetFilecopyToolExec indicates execution of a network file copy tool.
	EventKindNetFilecopyToolExec EventKind = "net_filecopy_tool_exec"

	// EventKindNetMITMToolExec indicates execution of a man-in-the-middle tool.
	EventKindNetMITMToolExec EventKind = "net_mitm_tool_exec"

	// EventKindNetScanToolExec indicates execution of a network scanning tool.
	EventKindNetScanToolExec EventKind = "net_scan_tool_exec"

	// EventKindNetSniffToolExec indicates execution of a network sniffing tool.
	EventKindNetSniffToolExec EventKind = "net_sniff_tool_exec"

	// EventKindNetSuspiciousToolExec indicates execution of a suspicious network tool.
	EventKindNetSuspiciousToolExec EventKind = "net_suspicious_tool_exec"

	// EventKindNetSuspiciousToolShell indicates a suspicious network tool started a shell.
	EventKindNetSuspiciousToolShell EventKind = "net_suspicious_tool_shell"

	// EventKindPasswdUsage indicates suspicious use of the passwd binary.
	EventKindPasswdUsage EventKind = "passwd_usage"

	// EventKindRuncSuspiciousExec indicates suspicious execution within runc.
	EventKindRuncSuspiciousExec EventKind = "runc_suspicious_exec"

	// EventKindWebserverExec indicates execution of a binary via a webserver.
	EventKindWebserverExec EventKind = "webserver_exec"

	// EventKindWebserverShellExec indicates a shell was spawned by a webserver.
	EventKindWebserverShellExec EventKind = "webserver_shell_exec"

	// EventKindCryptoMinerExecution indicates a crypto miner was executed.
	EventKindCryptoMinerExecution EventKind = "crypto_miner_execution"

	// EventKindAdultDomainAccess indicates access to an adult content domain.
	EventKindAdultDomainAccess EventKind = "adult_domain_access"

	// EventKindBadwareDomainAccess indicates access to a known malicious domain.
	EventKindBadwareDomainAccess EventKind = "badware_domain_access"

	// EventKindDynDNSDomainAccess indicates access to a dynamic DNS domain.
	EventKindDynDNSDomainAccess EventKind = "dyndns_domain_access"

	// EventKindFakeDomainAccess indicates access to a fake or impersonating domain.
	EventKindFakeDomainAccess EventKind = "fake_domain_access"

	// EventKindGamblingDomainAccess indicates access to a gambling-related domain.
	EventKindGamblingDomainAccess EventKind = "gambling_domain_access"

	// EventKindPiracyDomainAccess indicates access to a piracy-related domain.
	EventKindPiracyDomainAccess EventKind = "piracy_domain_access"

	// EventKindPlaintextCommunication indicates unencrypted/plaintext network communication.
	EventKindPlaintextCommunication EventKind = "plaintext_communication"

	// EventKindThreatDomainAccess indicates access to a threat-related domain.
	EventKindThreatDomainAccess EventKind = "threat_domain_access"

	// EventKindTrackingDomainAccess indicates access to a tracking or analytics domain.
	EventKindTrackingDomainAccess EventKind = "tracking_domain_access"

	// EventKindVPNLikeDomainAccess indicates access to a domain resembling a VPN or proxy.
	EventKindVPNLikeDomainAccess EventKind = "vpnlike_domain_access"
)

// OK checks if the EventKind is valid.
func (k EventKind) OK() bool {
	for _, allowed := range [...]EventKind{
		EventKindDropIP,
		EventKindDropDomain,
		EventKindFlow,
		EventKindCapabilitiesModification,
		EventKindCodeModificationThroughProcfs,
		EventKindCorePatternAccess,
		EventKindCPUFingerprint,
		EventKindCredentialsFilesAccess,
		EventKindFilesystemFingerprint,
		EventKindJavaDebugLibLoad,
		EventKindJavaInstrumentLibLoad,
		EventKindMachineFingerprint,
		EventKindOSFingerprint,
		EventKindOSNetworkFingerprint,
		EventKindOSStatusFingerprint,
		EventKindPackageRepoConfigModification,
		EventKindPAMConfigModification,
		EventKindSchedDebugAccess,
		EventKindShellConfigModification,
		EventKindSSLCertificateAccess,
		EventKindSudoersModification,
		EventKindSysrqAccess,
		EventKindUnprivilegedBPFConfigAccess,
		EventKindGlobalShlibModification,
		EventKindEnvironReadFromProcfs,
		EventKindBinarySelfDeletion,
		EventKindCryptoMinerFiles,
		EventKindAuthLogsTamper,
		EventKindBinaryExecutedByLoader,
		EventKindCodeOnTheFly,
		EventKindDataEncoderExec,
		EventKindDenialOfServiceTools,
		EventKindExecFromUnusualDir,
		EventKindFileAttributeChange,
		EventKindHiddenELFExec,
		EventKindInterpreterShellSpawn,
		EventKindNetFilecopyToolExec,
		EventKindNetMITMToolExec,
		EventKindNetScanToolExec,
		EventKindNetSniffToolExec,
		EventKindNetSuspiciousToolExec,
		EventKindNetSuspiciousToolShell,
		EventKindPasswdUsage,
		EventKindRuncSuspiciousExec,
		EventKindWebserverExec,
		EventKindWebserverShellExec,
		EventKindCryptoMinerExecution,
		EventKindAdultDomainAccess,
		EventKindBadwareDomainAccess,
		EventKindDynDNSDomainAccess,
		EventKindFakeDomainAccess,
		EventKindGamblingDomainAccess,
		EventKindPiracyDomainAccess,
		EventKindPlaintextCommunication,
		EventKindThreatDomainAccess,
		EventKindTrackingDomainAccess,
		EventKindVPNLikeDomainAccess,
	} {
		if k == allowed {
			return true
		}
	}

	return false
}

// Validate checks if the Event is valid.
func (e *Event) Validate() error {
	if e.ID == "" {
		return ErrIDcannotBeEmpty
	}

	// Use V2 ashkaal kind validation
	switch e.Kind {
	case kind.KindFlows, kind.KindDetections, kind.KindInfos, kind.KindNetPolicy:
		// Valid kinds
	case kind.KindNone, kind.KindEmpty:
		return ErrInvalidEventKind
	default:
		return ErrInvalidEventKind
	}

	return nil
}

// Event is something that happened in the system.
// This is used for retrieving events and includes the full agent details.
// Now uses V2 ashkaal format.
type Event struct {
	ID        string       `json:"id"`
	Agent     Agent        `json:"agent"`
	Data      ongoing.Base `json:"data"`
	Kind      kind.Kind    `json:"kind"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// EventData is the data associated with an event.
type EventData struct {
	// Fields for the regular structure
	Dropped     *DroppedIP `json:"dropped,omitempty"`
	Flow        *Flow      `json:"flow,omitempty"`
	FullInfo    *FullInfo  `json:"full_info,omitempty"`
	Parent      *Process   `json:"parent,omitempty"`
	Process     *Process   `json:"process,omitempty"`
	Resolve     *string    `json:"resolve,omitempty"`
	ResolveFlow *Flow      `json:"resolve_flow,omitempty"`
	Note        *string    `json:"note,omitempty"`
	Head        *EventHead `json:"head,omitempty"`

	// Fields for the new nested structure
	Body *EventBody `json:"body,omitempty"`

	// For timestamp in new format
	Timestamp *time.Time `json:"timestamp,omitempty"`
	UniqueID  *string    `json:"unique_id,omitempty"`
}

// EventBody represents the nested body structure in the new format.
type EventBody struct {
	Dropped  *DroppedIP `json:"dropped,omitempty"`
	FullInfo *FullInfo  `json:"full_info,omitempty"`
	Parent   *Process   `json:"parent,omitempty"`
	Process  *Process   `json:"process,omitempty"`
}

// EventHead represents the metadata for an event.
type EventHead struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Format        string `json:"format"`
	Description   string `json:"description"`
	Documentation string `json:"documentation"`
	Category      string `json:"category"`
	Mechanism     string `json:"mechanism"`
	Method        string `json:"method"`
	Importance    string `json:"importance"`
}

// DroppedIP represents an IP drop event.
type DroppedIP struct {
	Icmp        *ICMP       `json:"icmp,omitempty"`
	IPVersion   *int        `json:"ip_version,omitempty"`
	Local       *Node       `json:"local,omitempty"`
	Properties  *Properties `json:"properties,omitempty"`
	Proto       *string     `json:"proto,omitempty"`
	Remote      *Node       `json:"remote,omitempty"`
	ServicePort *int        `json:"service_port,omitempty"`
	Settings    *Settings   `json:"settings,omitempty"`
}

// FullInfo represents the full information of an event.
type FullInfo struct {
	Ancestry *[]Process                         `json:"ancestry,omitempty"`
	Files    *map[string]map[string]interface{} `json:"files,omitempty"`
	Flows    *[]FlowSimple                      `json:"flows,omitempty"`
}

// FlowSimple represents a network flow event.
type FlowSimple struct {
	Icmp        *ICMP     `json:"icmp,omitempty"`
	IPVersion   *int      `json:"ip_version,omitempty"`
	Local       *Node     `json:"local,omitempty"`
	Proto       *string   `json:"proto,omitempty"`
	Remote      *Node     `json:"remote,omitempty"`
	ServicePort *int      `json:"service_port,omitempty"`
	Settings    *Settings `json:"settings,omitempty"`
}

// Flow represents a network flow event with additional properties.
type Flow struct {
	FlowSimple

	Properties *Properties `json:"properties,omitempty"`
}

// Properties represents the properties of a flow.
type Properties struct {
	Egress     *bool `json:"egress,omitempty"`
	Ended      *bool `json:"ended,omitempty"`
	Incoming   *bool `json:"incoming,omitempty"`
	Ingress    *bool `json:"ingress,omitempty"`
	Ongoing    *bool `json:"ongoing,omitempty"`
	Outgoing   *bool `json:"outgoing,omitempty"`
	Started    *bool `json:"started,omitempty"`
	Terminated *bool `json:"terminated,omitempty"`
	Terminator *bool `json:"terminator,omitempty"`
}

// Settings represents the settings for a flow.
type Settings struct {
	Direction   *string `json:"direction,omitempty"`
	EndedBy     *string `json:"ended_by,omitempty"`
	InitiatedBy *string `json:"initiated_by,omitempty"`
	Status      *string `json:"status,omitempty"`
}

// Node represents a network node.
type Node struct {
	Address *string   `json:"address,omitempty"`
	Name    *string   `json:"name,omitempty"`
	Names   *[]string `json:"names,omitempty"`
	Port    *int      `json:"port,omitempty"`
}

// ICMP represents the Internet Control Message Protocol (ICMP) settings.
type ICMP struct {
	Code *string `json:"code,omitempty"`
	Type *string `json:"type,omitempty"`
}

// Process represents the process information associated with an event.
type Process struct {
	Args       *string    `json:"args,omitempty"`
	Cmd        *string    `json:"cmd,omitempty"`
	Comm       *string    `json:"comm,omitempty"`
	Exe        *string    `json:"exe,omitempty"`
	Exit       *string    `json:"exit,omitempty"`
	Loader     *string    `json:"loader,omitempty"`
	PID        *int       `json:"pid,omitempty"`
	PpID       *int       `json:"ppid,omitempty"`
	PrevArgs   *string    `json:"prev_args,omitempty"`
	PrevExe    *string    `json:"prev_exe,omitempty"`
	PrevLoader *string    `json:"prev_loader,omitempty"`
	Retcode    *int       `json:"retcode,omitempty"`
	Start      *time.Time `json:"start,omitempty"`
	UID        *int       `json:"uid,omitempty"`
}


// EventWrapper is a wrapper struct for unmarshaling events in the new format.
type EventWrapper struct {
	Data EventData `json:"data"`
	Type string    `json:"type"`
}
