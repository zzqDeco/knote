package repository

import (
	"context"
	"errors"
	"time"

	"github.com/zzqDeco/knote/internal/protocol"
)

var ErrRemoteNotImplemented = errors.New("remote repository is not implemented")

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

type Sessions interface {
	Append(ctx context.Context, event protocol.Event) error
	Load(ctx context.Context, sessionID string) ([]protocol.Event, error)
	List(ctx context.Context, limit int) ([]SessionSummary, error)
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
	Workspace   string
	Permissions PermissionConfig
	KAG         KAGConfig
	Models      map[string]ModelProfile
}

type PermissionConfig struct {
	BuildDefault string
	GitDefault   string
}

type KAGConfig struct {
	AdapterPath string
	Host        string
	Fake        bool
	ConfigPath  string
	ProjectID   string
	Namespace   string
	Language    string
	RuntimeDir  string
}

type ModelProfile struct {
	Provider string
	Model    string
	BaseURL  string
}

type Source struct {
	Path    string
	Size    int64
	ModTime time.Time
}

type ArtifactSet struct {
	Manifest    protocol.ArtifactManifest
	Documents   []protocol.Document
	Chunks      []protocol.Chunk
	Entities    []protocol.Entity
	Relations   []protocol.Relation
	Claims      []protocol.Claim
	Summaries   []protocol.Summary
	SchemaYAML  string
	BuildReport string
}

type EvalQuestion struct {
	ID       string
	Question string
}

type EvalResult struct {
	ID            string
	Question      string
	KnowledgeHash string
	Answer        string
	Evidence      []string
	Explanation   string
	Uncertainty   string
	Mode          string
	AdapterError  string
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
