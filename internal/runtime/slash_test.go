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

func TestPermissionedSlashRejectsProtectedAndUnknownCommandsUniformly(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	const canary = "restricted-command-canary"
	executor := &fakeToolExecutor{events: []protocol.Event{
		protocol.NewEvent(protocol.EventVersionDiff, "", canary, map[string]string{"diff": canary}),
	}}
	providerCalls := 0
	rt := New(Dependencies{
		Workspace:    workspace,
		Capabilities: PermissionedSessionCapabilityProfile(),
		Sessions:     store,
		Versions:     store,
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "natural answer", nil)}},
		AuthorizationContextProvider: func(ctx context.Context, sessionID string) (protocol.AuthorizationContext, error) {
			providerCalls++
			return testAuthorizationContextProvider(ctx, sessionID)
		},
		ToolExecutor: executor,
		NewSessionID: func() string { return "sess_permissioned_commands" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	commands := []string{"/details", "/versions", "/status", "/settings", "/model", "/diff", "/eval", "/unknown"}
	for _, command := range commands {
		events := rt.SendMessage(context.Background(), command)
		assertEventsExcludeCanary(t, events, canary)
		var rejection string
		for _, event := range events {
			if event.Type == protocol.EventError {
				rejection = event.Message
			}
		}
		if rejection != permissionedCommandUnavailableMessage {
			t.Fatalf("permissioned %s rejection = %q, want %q", command, rejection, permissionedCommandUnavailableMessage)
		}
	}
	if executor.calls != 0 {
		t.Fatalf("permissioned rejected commands invoked raw tool %d time(s)", executor.calls)
	}
	if providerCalls != 0 {
		t.Fatalf("permissioned rejected commands reached authorization provider %d time(s)", providerCalls)
	}
	persisted, err := store.Load(context.Background(), rt.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	assertEventsExcludeCanary(t, persisted, canary)
}

func TestPermissionedSlashHelpListsOnlyAvailableCommands(t *testing.T) {
	workspace := t.TempDir()
	store := local.New(workspace)
	rt := New(Dependencies{
		Workspace:    workspace,
		Capabilities: PermissionedSessionCapabilityProfile(),
		Sessions:     store,
		EinoRunner:   &fakeEinoRunner{events: []protocol.Event{protocol.NewEvent(protocol.EventAssistantDone, "", "unused", nil)}},
		NewSessionID: func() string { return "sess_permissioned_help" },
	})
	if _, err := rt.Start(context.Background(), StartOptions{}); err != nil {
		t.Fatal(err)
	}

	events := rt.SendMessage(context.Background(), "/help")
	var help string
	for _, event := range events {
		if event.Type == protocol.EventAssistantDone {
			help = event.Message
		}
	}
	for _, command := range []string{"build", "commit", "release", "checkout", "tasks", "clear", "new", "resume", "help", "exit"} {
		if !strings.Contains(help, "/"+command) {
			t.Fatalf("permissioned help omitted /%s: %q", command, help)
		}
	}
	for _, command := range []string{"details", "versions", "status", "settings", "model", "diff", "eval"} {
		if strings.Contains(help, "/"+command) {
			t.Fatalf("permissioned help exposed /%s: %q", command, help)
		}
	}
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
