package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository/local"
)

func TestCheckoutSlashPassesActualDirtyStateToTool(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	mustRun(t, workspace, "git", "config", "user.email", "knote@example.com")
	mustRun(t, workspace, "git", "config", "user.name", "knote")
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, ".gitignore"), []byte(".knote/sessions/\n"), 0o644))
	introPath := filepath.Join(workspace, "sources", "intro.md")
	must(t, os.WriteFile(introPath, []byte("clean\n"), 0o644))
	mustRun(t, workspace, "git", "add", ".")
	mustRun(t, workspace, "git", "commit", "-m", "initial")

	store := local.New(workspace)
	executor := &fakeToolExecutor{}
	rt := New(Dependencies{
		Workspace:    workspace,
		Sessions:     store,
		Versions:     store,
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "natural answer", nil)}},
		ToolExecutor: executor,
		NewSessionID: func() string { return "sess_checkout" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	rt.SendMessage(context.Background(), "/checkout HEAD")
	if executor.lastTool != einotools.NameCheckout || executor.lastArgs != `{"allow_dirty":false,"ref":"HEAD"}` {
		t.Fatalf("clean checkout tool call = %s %s", executor.lastTool, executor.lastArgs)
	}

	must(t, os.WriteFile(introPath, []byte("dirty\n"), 0o644))
	rt.SendMessage(context.Background(), "/checkout HEAD")
	if executor.lastTool != einotools.NameCheckout || executor.lastArgs != `{"allow_dirty":true,"ref":"HEAD"}` {
		t.Fatalf("dirty checkout tool call = %s %s", executor.lastTool, executor.lastArgs)
	}
}
