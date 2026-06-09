package remote

import (
	"context"

	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

type Provider string

const (
	ProviderGitHub Provider = "github"
	ProviderGitea  Provider = "gitea"
	ProviderGitLab Provider = "gitlab"
	ProviderCustom Provider = "custom"
)

type Config struct {
	Provider       Provider
	BaseURL        string
	Owner          string
	Repository     string
	DefaultBaseRef string
	AuthRef        string
}

type Ref struct {
	Name string
	SHA  string
}

type DraftTree struct {
	ID      string
	BaseRef Ref
	Files   []DraftFile
}

type DraftFile struct {
	Path        string
	ContentHash string
	Operation   DraftOperation
}

type DraftOperation string

const (
	DraftUpsert DraftOperation = "upsert"
	DraftDelete DraftOperation = "delete"
)

type CommitProposal struct {
	Branch  string
	Message string
	Tree    DraftTree
}

type MergeRequest struct {
	ID        string
	URL       string
	SourceRef Ref
	TargetRef Ref
	State     MergeRequestState
}

type MergeRequestState string

const (
	MergeRequestDraft  MergeRequestState = "draft"
	MergeRequestOpen   MergeRequestState = "open"
	MergeRequestMerged MergeRequestState = "merged"
	MergeRequestClosed MergeRequestState = "closed"
)

type Release struct {
	Tag       string
	TargetRef Ref
	Name      string
	URL       string
}

// Store is a future remote repository implementation placeholder. It explicitly
// models remote concepts instead of pretending remote state has a local dirty tree.
type Store struct {
	cfg Config
}

func New(cfg Config) Store {
	return Store{cfg: cfg}
}

func (s Store) RemoteConfig() Config {
	return s.cfg
}

func (s Store) Config(context.Context) (repository.Config, error) {
	return repository.Config{}, repository.ErrRemoteNotImplemented
}

func (s Store) SaveConfig(context.Context, repository.Config) error {
	return repository.ErrRemoteNotImplemented
}

func (s Store) ListSources(context.Context) ([]repository.Source, error) {
	return nil, repository.ErrRemoteNotImplemented
}

func (s Store) ReadSource(context.Context, string) ([]byte, error) {
	return nil, repository.ErrRemoteNotImplemented
}

func (s Store) WriteArtifacts(context.Context, repository.ArtifactSet) error {
	return repository.ErrRemoteNotImplemented
}

func (s Store) ReadManifest(context.Context) (protocol.ArtifactManifest, error) {
	return protocol.ArtifactManifest{}, repository.ErrRemoteNotImplemented
}

func (s Store) ReadSummaries(context.Context) ([]protocol.Summary, error) {
	return nil, repository.ErrRemoteNotImplemented
}

func (s Store) LoadQuestions(context.Context) ([]repository.EvalQuestion, error) {
	return nil, repository.ErrRemoteNotImplemented
}

func (s Store) WriteEval(context.Context, repository.EvalReport) error {
	return repository.ErrRemoteNotImplemented
}

func (s Store) EvalGate(context.Context) error {
	return repository.ErrRemoteNotImplemented
}

func (s Store) Append(context.Context, protocol.Event) error {
	return repository.ErrRemoteNotImplemented
}

func (s Store) Load(context.Context, string) ([]protocol.Event, error) {
	return nil, repository.ErrRemoteNotImplemented
}

func (s Store) List(context.Context, int) ([]repository.SessionSummary, error) {
	return nil, repository.ErrRemoteNotImplemented
}

func (s Store) Status(context.Context) (repository.Status, error) {
	return repository.Status{}, repository.ErrRemoteNotImplemented
}

func (s Store) Diff(context.Context, string) (string, error) {
	return "", repository.ErrRemoteNotImplemented
}

func (s Store) Versions(context.Context, int) ([]repository.Version, error) {
	return nil, repository.ErrRemoteNotImplemented
}

func (s Store) Commit(context.Context, string) (repository.CommitResult, error) {
	return repository.CommitResult{}, repository.ErrRemoteNotImplemented
}

func (s Store) Tag(context.Context, string) error {
	return repository.ErrRemoteNotImplemented
}

func (s Store) Checkout(context.Context, string, repository.CheckoutOptions) error {
	return repository.ErrRemoteNotImplemented
}
