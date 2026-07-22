package repository

import (
	"context"
	"errors"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var (
	ErrRemoteNotImplemented                 = errors.New("remote repository is not implemented")
	ErrArtifactPublicationStaleBase         = errors.New("artifact publication base is stale")
	ErrSessionAuthorizationEnvelopeNotFound = errors.New("session authorization envelope not found")
)

// ArtifactPublicationBase identifies the public artifact pointer that a
// candidate was built from. Absent is explicit so an initial publication
// cannot accidentally match an arbitrary current pointer.
type ArtifactPublicationBase struct {
	ProjectionVersion string
	Absent            bool
}

func (b ArtifactPublicationBase) Validate() error {
	if b.Absent {
		if b.ProjectionVersion != "" {
			return errors.New("absent artifact publication base cannot have a projection version")
		}
		return nil
	}
	if b.ProjectionVersion == "" {
		return errors.New("artifact publication base projection version is required")
	}
	return nil
}

type Workspace interface {
	Config(ctx context.Context) (Config, error)
	SaveConfig(ctx context.Context, cfg Config) error

	ListSources(ctx context.Context) ([]Source, error)
	ReadSource(ctx context.Context, path string) ([]byte, error)

	WriteArtifacts(ctx context.Context, set ArtifactSet) error
	ReadManifest(ctx context.Context) (protocol.ArtifactManifest, error)
	ReadSummaries(ctx context.Context) ([]protocol.Summary, error)

	LoadQuestions(ctx context.Context) ([]EvalQuestion, error)
	WriteEval(ctx context.Context, report EvalReport) error
	EvalGate(ctx context.Context) error
}

// ProjectionWorkspace is a workspace that can stage an immutable artifact
// bundle and atomically select it for serving.
type ProjectionWorkspace interface {
	Workspace
	StageArtifacts(ctx context.Context, set ArtifactSet) error
	PublishArtifacts(ctx context.Context, base ArtifactPublicationBase, manifest protocol.ArtifactBundleManifest) error
	ReadCurrentArtifactManifest(ctx context.Context) (protocol.ArtifactBundleManifest, error)
	ReadCurrentProjection(ctx context.Context) ([]byte, error)
}

// SelectedArtifactBundle is an immutable, fully verified serving snapshot.
// Files contains exactly the descriptors declared by Manifest.
type SelectedArtifactBundle struct {
	Manifest protocol.ArtifactBundleManifest
	Files    map[string][]byte
}

// SelectedArtifactMetadata contains only the verified authorization metadata
// needed before an authorization decision. It must not contain evidence bytes.
type SelectedArtifactMetadata struct {
	Manifest       protocol.ArtifactBundleManifest
	ProjectionJSON []byte
}

// SelectedArtifactReader separates pre-authorization metadata from the full
// selected bundle while keeping both reads coherent and independently verified.
type SelectedArtifactReader interface {
	ReadCurrentArtifactMetadata(context.Context) (SelectedArtifactMetadata, error)
	ReadCurrentArtifactBundle(context.Context) (SelectedArtifactBundle, error)
}

type Sessions interface {
	Append(ctx context.Context, event protocol.Event) error
	AppendBatch(ctx context.Context, events []protocol.Event) error
	Load(ctx context.Context, sessionID string) ([]protocol.Event, error)
	List(ctx context.Context, limit int) ([]SessionSummary, error)
}

type PermissionedSessions interface {
	Sessions
	BindAuthorization(ctx context.Context, envelope protocol.SessionAuthorizationEnvelope) error
	LoadAuthorization(ctx context.Context, sessionID string) (protocol.SessionAuthorizationEnvelope, error)
	ListAuthorization(ctx context.Context) ([]protocol.SessionAuthorizationEnvelope, error)
}

// RebindablePermissionedSessions supports an explicit compare-and-swap
// transition after a confirmed artifact scope change. Ordinary session binds
// remain immutable through PermissionedSessions.BindAuthorization.
type RebindablePermissionedSessions interface {
	PermissionedSessions
	RebindAuthorization(ctx context.Context, expected, replacement protocol.SessionAuthorizationEnvelope) error
}

type Versions interface {
	Status(ctx context.Context) (Status, error)
	Diff(ctx context.Context, ref string) (string, error)
	Versions(ctx context.Context, limit int) ([]Version, error)
	Commit(ctx context.Context, message string) (CommitResult, error)
	Tag(ctx context.Context, tag string) error
	Checkout(ctx context.Context, ref string, opts CheckoutOptions) error
}

type Config struct {
	Workspace   string                  `yaml:"workspace"`
	Permissions PermissionConfig        `yaml:"permissions"`
	KAG         KAGConfig               `yaml:"kag"`
	Models      map[string]ModelProfile `yaml:"models"`
}

type PermissionConfig struct {
	BuildDefault string `yaml:"build_default"`
	GitDefault   string `yaml:"git_default"`
}

type KAGConfig struct {
	AdapterPath string `yaml:"adapter_path"`
	Host        string `yaml:"host"`
	Fake        bool   `yaml:"fake"`
	ConfigPath  string `yaml:"config_path,omitempty"`
	ProjectID   string `yaml:"project_id,omitempty"`
	Namespace   string `yaml:"namespace,omitempty"`
	Language    string `yaml:"language,omitempty"`
	RuntimeDir  string `yaml:"runtime_dir,omitempty"`
}

type ModelProfile struct {
	Provider string `yaml:"provider"`
	Model    string `yaml:"model"`
	BaseURL  string `yaml:"base_url,omitempty"`
}

type Source struct {
	Path    string
	Size    int64
	ModTime time.Time
}

type ArtifactSet struct {
	Manifest                protocol.ArtifactManifest
	BundleManifest          protocol.ArtifactBundleManifest
	ProjectionJSON          []byte
	ProjectionResourceCount int
	Documents               []protocol.Document
	Chunks                  []protocol.Chunk
	Entities                []protocol.Entity
	Relations               []protocol.Relation
	Claims                  []protocol.Claim
	GraphBindings           []protocol.GraphResourceBinding
	ClaimBindings           []protocol.ClaimTripleBinding
	Summaries               []protocol.Summary
	SchemaYAML              string
	BuildReport             string
}

type EvalQuestion struct {
	ID       string `json:"id"`
	Question string `json:"question"`
}

type EvalResult struct {
	ID            string   `json:"id"`
	Question      string   `json:"question"`
	KnowledgeHash string   `json:"knowledge_hash,omitempty"`
	Answer        string   `json:"answer"`
	Evidence      []string `json:"evidence"`
	Explanation   string   `json:"explanation,omitempty"`
	Uncertainty   string   `json:"uncertainty,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	AdapterError  string   `json:"adapter_error,omitempty"`
}

type EvalReport struct {
	Results        []EvalResult
	Total          int
	AdapterErrors  int
	KnowledgeHash  string
	ReportMarkdown string
}

type SessionSummary struct {
	ID          string
	EventCount  int
	LastEventAt time.Time
	UpdatedAt   time.Time
}

type Status struct {
	Branch string
	Dirty  bool
	Raw    string
}

type Version struct {
	Hash         string
	ShortHash    string
	Subject      string
	RelativeTime string
	Tags         []string
	Current      bool
}

type CommitResult struct {
	Hash    string
	Summary string
	Output  string
}

type CheckoutOptions struct {
	AllowDirty bool
}
