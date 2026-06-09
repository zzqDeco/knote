package repository

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/zzqDeco/knote/internal/protocol"
)

func TestInterfaceCompileContracts(t *testing.T) {
	var _ Workspace = noopWorkspace{}
	var _ Sessions = noopSessions{}
	var _ Versions = noopVersions{}
}

func TestRepositoryPackageImportBoundary(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", ".").Output()
	if err != nil {
		t.Fatalf("go list repository imports: %v", err)
	}
	for _, forbidden := range []string{
		"/internal/agent",
		"/internal/knowledge",
		"/internal/repository/local",
		"/internal/repository/remote",
	} {
		if strings.Contains(string(out), forbidden) {
			t.Fatalf("repository imports forbidden package %s:\n%s", forbidden, out)
		}
	}
}

type noopWorkspace struct{}

func (noopWorkspace) Config(context.Context) (Config, error)             { return Config{}, nil }
func (noopWorkspace) SaveConfig(context.Context, Config) error           { return nil }
func (noopWorkspace) ListSources(context.Context) ([]Source, error)      { return nil, nil }
func (noopWorkspace) ReadSource(context.Context, string) ([]byte, error) { return nil, nil }
func (noopWorkspace) WriteArtifacts(context.Context, ArtifactSet) error  { return nil }
func (noopWorkspace) ReadManifest(context.Context) (protocol.ArtifactManifest, error) {
	return protocol.ArtifactManifest{}, nil
}
func (noopWorkspace) ReadSummaries(context.Context) ([]protocol.Summary, error) { return nil, nil }
func (noopWorkspace) LoadQuestions(context.Context) ([]EvalQuestion, error)     { return nil, nil }
func (noopWorkspace) WriteEval(context.Context, EvalReport) error               { return nil }
func (noopWorkspace) EvalGate(context.Context) error                            { return nil }

type noopSessions struct{}

func (noopSessions) Append(context.Context, protocol.Event) error           { return nil }
func (noopSessions) Load(context.Context, string) ([]protocol.Event, error) { return nil, nil }
func (noopSessions) List(context.Context, int) ([]SessionSummary, error)    { return nil, nil }

type noopVersions struct{}

func (noopVersions) Status(context.Context) (Status, error)           { return Status{}, nil }
func (noopVersions) Diff(context.Context, string) (string, error)     { return "", nil }
func (noopVersions) Versions(context.Context, int) ([]Version, error) { return nil, nil }
func (noopVersions) Commit(context.Context, string) (CommitResult, error) {
	return CommitResult{}, nil
}
func (noopVersions) Tag(context.Context, string) error                       { return nil }
func (noopVersions) Checkout(context.Context, string, CheckoutOptions) error { return nil }
