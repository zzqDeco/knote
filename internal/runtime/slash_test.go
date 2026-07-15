package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
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

func TestPermissionedSlashBlocksRawDiff(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	const canary = "restricted-diff-canary"
	executor := &fakeToolExecutor{events: []protocol.Event{
		protocol.NewEvent(protocol.EventVersionDiff, "", canary, map[string]string{"diff": canary}),
	}}
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		Versions:                     store,
		EinoRunner:                   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "natural answer", nil)}},
		AuthorizationContextProvider: testAuthorizationContextProvider,
		ToolExecutor:                 executor,
		NewSessionID:                 func() string { return "sess_permissioned_diff" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	events := rt.SendMessage(context.Background(), "/diff")
	if executor.calls != 0 {
		t.Fatalf("permissioned /diff invoked raw tool %d time(s)", executor.calls)
	}
	assertEventsExcludeCanary(t, events, canary)
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "diff is unavailable in permissioned sessions") {
		t.Fatalf("permissioned /diff response did not explain the block: %s", encoded)
	}
	persisted, err := store.Load(context.Background(), rt.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	assertEventsExcludeCanary(t, persisted, canary)
}

func TestPermissionedSlashStatusOmitsRawPaths(t *testing.T) {
	workspace := t.TempDir()
	mustRun(t, workspace, "git", "init")
	mustRun(t, workspace, "git", "config", "user.email", "knote@example.com")
	mustRun(t, workspace, "git", "config", "user.name", "knote")
	must(t, os.MkdirAll(filepath.Join(workspace, "sources"), 0o755))
	must(t, os.WriteFile(filepath.Join(workspace, "sources", "intro.md"), []byte("initial\n"), 0o644))
	mustRun(t, workspace, "git", "add", ".")
	mustRun(t, workspace, "git", "commit", "-m", "initial")
	const canary = "restricted-status-canary.md"
	must(t, os.WriteFile(filepath.Join(workspace, "sources", canary), []byte("restricted\n"), 0o644))

	store := local.New(workspace)
	rt := New(Dependencies{
		Workspace:                    workspace,
		Sessions:                     store,
		Versions:                     store,
		EinoRunner:                   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "natural answer", nil)}},
		AuthorizationContextProvider: testAuthorizationContextProvider,
		NewSessionID:                 func() string { return "sess_permissioned_status" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	events := rt.SendMessage(context.Background(), "/status")
	assertEventsExcludeCanary(t, events, canary)
	foundStatus := false
	for _, event := range events {
		if event.Type != protocol.EventStatusUpdate {
			continue
		}
		foundStatus = true
		status, ok := event.Payload.(repository.Status)
		if !ok {
			t.Fatalf("status payload type = %T, want repository.Status", event.Payload)
		}
		if status.Raw != "" || !status.Dirty {
			t.Fatalf("permissioned status payload = %+v, want dirty aggregate without raw paths", status)
		}
	}
	if !foundStatus {
		t.Fatal("permissioned /status produced no status event")
	}
	persisted, err := store.Load(context.Background(), rt.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	assertEventsExcludeCanary(t, persisted, canary)
}

func assertEventsExcludeCanary(t *testing.T, events []protocol.Event, canary string) {
	t.Helper()
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), canary) {
		t.Fatalf("event stream leaked %q: %s", canary, encoded)
	}
}
