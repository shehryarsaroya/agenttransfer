// Package apphost provides the narrow, authenticated boundary between the
// AgentTransfer server and the local container runtime used for dynamic apps.
//
// The server-facing half is a JSON HTTP client over a Unix socket. Only the
// runner process invokes Docker; callers never provide command-line fragments.
package apphost

import (
	"os"
	"time"
)

const (
	apiPrefix            = "/v1"
	defaultImagePrefix   = "agenttransfer-app"
	defaultContainerPort = 8080
)

// RunnerConfig configures the isolated runner. Resource values are fixed
// runner-side ceilings, not request-controlled knobs.
type RunnerConfig struct {
	SocketPath string
	// SocketMode defaults to 0660. 0666 is explicitly supported for
	// deployments where runner and server use unrelated DynamicUser IDs; the
	// 256-bit bearer token remains mandatory on every request.
	SocketMode os.FileMode
	// SocketGID changes the socket group when positive; zero leaves it as the
	// runner process's group.
	SocketGID   int
	AuthToken   string
	AppRoot     string
	DockerPath  string
	ImagePrefix string
	// BuildNetwork controls network access for Dockerfile RUN instructions:
	// "none" (default) or "bridge". Base-image pulls remain allowed.
	BuildNetwork string

	CommandTimeout time.Duration
	BuildTimeout   time.Duration
	PullTimeout    time.Duration
	HealthTimeout  time.Duration
	MaxOutputBytes int64
	MaxLogLines    int

	CPUCount       float64
	MemoryBytes    int64
	PIDsLimit      int64
	TmpfsSizeBytes int64
	ContainerPort  int
	// ContainerUID/GID default to the unprivileged 65532:65532 identity.
	// They exist primarily for rootless runner installations and tests; zero
	// is never accepted.
	ContainerUID int
	ContainerGID int
}

// ClientConfig configures a runner client.
type ClientConfig struct {
	SocketPath string
	AuthToken  string
	Timeout    time.Duration
	// MaxResponseBytes bounds JSON responses, including build output and logs.
	MaxResponseBytes int64
}

// BuildRequest asks the runner to build a managed image from an already
// materialized context. ContextDir must resolve beneath RunnerConfig.AppRoot.
// The runner derives the image name; arbitrary tags are never passed through.
type BuildRequest struct {
	AppID      string `json:"app_id"`
	ReleaseID  string `json:"release_id"`
	ContextDir string `json:"context_dir"`
}

type BuildResult struct {
	AppID           string `json:"app_id"`
	ReleaseID       string `json:"release_id"`
	Image           string `json:"image"`
	Output          string `json:"output,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
}

type BuildResponse = BuildResult

// DeployRequest starts a previously built managed image. ContainerPort and
// HealthPath describe the app inside the container; Docker chooses a random
// loopback-only host port.
type DeployRequest struct {
	AppID         string            `json:"app_id"`
	ReleaseID     string            `json:"release_id"`
	Image         string            `json:"image"`
	ContainerPort int               `json:"container_port,omitempty"`
	HealthPath    string            `json:"health_path,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	// Command is passed as the container argv after the image name. It is
	// never joined, interpreted by a shell, or accepted as a string fragment.
	Command []string `json:"command,omitempty"`
}

type DeployResponse struct {
	AppID         string `json:"app_id"`
	ReleaseID     string `json:"release_id"`
	RuntimeID     string `json:"runtime_id"`
	ContainerName string `json:"container_name"`
	Upstream      string `json:"upstream"`
	Image         string `json:"image"`
	Healthy       bool   `json:"healthy"`
	DataBytes     int64  `json:"data_bytes"`
}

// DeployResult is retained as a descriptive alias for callers that model
// operation results rather than wire responses.
type DeployResult = DeployResponse

// AppStatus is the runner's view of one managed container.
type AppStatus struct {
	AppID         string `json:"app_id"`
	ReleaseID     string `json:"release_id"`
	Image         string `json:"image"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	State         string `json:"state"`
	Running       bool   `json:"running"`
	ExitCode      int    `json:"exit_code"`
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	URL           string `json:"url,omitempty"`
	StartedAt     string `json:"started_at,omitempty"`
	FinishedAt    string `json:"finished_at,omitempty"`
	DataBytes     int64  `json:"data_bytes"`
}

type LogsResult struct {
	AppID     string `json:"app_id"`
	Lines     int    `json:"lines"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated,omitempty"`
}

type StopResult struct {
	AppID      string   `json:"app_id,omitempty"`
	RuntimeID  string   `json:"runtime_id,omitempty"`
	Stopped    bool     `json:"stopped"`
	StoppedIDs []string `json:"stopped_ids,omitempty"`
}

type RemoveResult struct {
	AppID     string `json:"app_id"`
	RuntimeID string `json:"runtime_id"`
	Removed   bool   `json:"removed"`
}

type RemoveAppResult struct {
	AppID           string `json:"app_id"`
	RemovedRuntimes int    `json:"removed_runtimes"`
}

type ReconcileRequest struct {
	KeepRuntimeID string `json:"keep_runtime_id"`
}

type ReconcileResult struct {
	AppID           string `json:"app_id"`
	KeptRuntimeID   string `json:"kept_runtime_id"`
	RemovedRuntimes int    `json:"removed_runtimes"`
}

type PurgeResult struct {
	AppID           string `json:"app_id"`
	RemovedRuntimes int    `json:"removed_runtimes"`
	DataRemoved     bool   `json:"data_removed"`
}

type healthResult struct {
	OK bool `json:"ok"`
}

type errorEnvelope struct {
	Error string `json:"error"`
}
