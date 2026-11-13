// Package event defines the normalized event and anomaly types shared by the
// collectors, the detection engine and the transport layer.
package event

import "time"

// Logsource values (Sigma logsource taxonomy).
const (
	ProductLinux = "linux"

	CategoryProcessCreation   = "process_creation"
	CategoryNetworkConnection = "network_connection"
	CategoryFileEvent         = "file_event"
	ServiceAuth               = "auth"
	ServiceSSHD               = "sshd"
	ServiceSyslog             = "syslog"
	ServiceAuditd             = "auditd"
	ServiceUsers              = "users"
)

// Kind is the collector-level normalized event type. Native detection rules
// key off Kind; Sigma rules key off the logsource and Sigma fields.
const (
	KindSSHFailed      = "ssh_failed"
	KindSSHAccepted    = "ssh_accepted"
	KindSSHInvalidUser = "ssh_invalid_user"
	KindSudo           = "sudo"
	KindSudoFailed     = "sudo_failed"
	KindSu             = "su"
	KindSuFailed       = "su_failed"
	KindUserAdd        = "user_add"
	KindUserMod        = "user_mod"
	KindGroupAdd       = "group_add"

	KindExec              = "exec"
	KindProcSuspiciousExe = "proc_suspicious_exe"
	KindProcDeletedExe    = "proc_deleted_exe"
	KindProcReverseShell  = "proc_reverse_shell"

	KindNetListen   = "net_listen"
	KindNetOutbound = "net_outbound"

	KindFileCreated  = "file_created"
	KindFileModified = "file_modified"
	KindFileDeleted  = "file_deleted"

	KindUserNew     = "user_new"
	KindUserNewUID0 = "user_new_uid0"
)

// Logsource identifies where an event came from in Sigma terms.
type Logsource struct {
	Product  string `json:"product,omitempty"`
	Category string `json:"category,omitempty"`
	Service  string `json:"service,omitempty"`
}

// Event is a normalized telemetry record using Sigma-standard field names.
// Only the fields relevant to an event's logsource are populated.
type Event struct {
	ID        string    `json:"id,omitempty"`
	Time      time.Time `json:"ts"`
	Source    string    `json:"source,omitempty"` // collector name
	Kind      string    `json:"kind,omitempty"`
	Logsource Logsource `json:"logsource"`

	// Process fields.
	Image             string `json:"Image,omitempty"`
	CommandLine       string `json:"CommandLine,omitempty"`
	ParentImage       string `json:"ParentImage,omitempty"`
	ParentCommandLine string `json:"ParentCommandLine,omitempty"`
	User              string `json:"User,omitempty"`
	ProcessId         int    `json:"ProcessId,omitempty"`
	ParentProcessId   int    `json:"ParentProcessId,omitempty"`
	CurrentDirectory  string `json:"CurrentDirectory,omitempty"`
	// ProcessStartTime is /proc starttime in clock ticks since boot (0 if unknown).
	ProcessStartTime uint64 `json:"ProcessStartTime,omitempty"`

	// Network fields.
	DestinationIp       string `json:"DestinationIp,omitempty"`
	DestinationPort     int    `json:"DestinationPort,omitempty"`
	DestinationHostname string `json:"DestinationHostname,omitempty"`
	SourceIp            string `json:"SourceIp,omitempty"`
	SourcePort          int    `json:"SourcePort,omitempty"`
	Initiated           bool   `json:"Initiated,omitempty"`

	// File fields.
	TargetFilename string `json:"TargetFilename,omitempty"`
	Sha256         string `json:"Sha256,omitempty"`

	// Auth / user fields.
	TargetUser string `json:"TargetUser,omitempty"`
	Message    string `json:"Message,omitempty"`

	Extra map[string]string `json:"extra,omitempty"`
}

// Severity levels per PROTOCOL.md.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Anomaly is the unit shipped to the server (PROTOCOL.md section 4).
type Anomaly struct {
	ID             string         `json:"id"`
	Ts             string         `json:"ts"`
	RuleID         string         `json:"rule_id"`
	RuleSource     string         `json:"rule_source"`
	RuleTitle      string         `json:"rule_title"`
	Category       string         `json:"category"`
	Severity       Severity       `json:"severity"`
	Fingerprint    string         `json:"fingerprint"`
	Summary        string         `json:"summary"`
	AttackTags     []string       `json:"attack_tags"`
	Falsepositives []string       `json:"falsepositives"`
	Shadow         bool           `json:"shadow"`
	Evidence       map[string]any `json:"evidence"`
}
