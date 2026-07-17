package identity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	processHelperModeEnv    = "KNOTE_IDENTITY_TEST_PROCESS_MODE"
	processHelperRootEnv    = "KNOTE_IDENTITY_TEST_PROCESS_ROOT"
	processHelperClockEnv   = "KNOTE_IDENTITY_TEST_PROCESS_CLOCK"
	processHelperReadyEnv   = "KNOTE_IDENTITY_TEST_PROCESS_READY"
	processHelperStartEnv   = "KNOTE_IDENTITY_TEST_PROCESS_START"
	processHelperValueEnv   = "KNOTE_IDENTITY_TEST_PROCESS_VALUE"
	processHelperExpiresEnv = "KNOTE_IDENTITY_TEST_PROCESS_EXPIRES"
	processHelperSuccess    = "IDENTITY_PROCESS_SUCCESS"
	processHelperReplay     = "IDENTITY_PROCESS_REPLAY"
)

func TestLocalStoreCrossProcessLocking(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	barriers := t.TempDir()
	now := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	scope := testScope("tenant-process")
	store := openTestStore(t, root, clock)
	registerTestTenant(t, store, scope)

	digest := replayDigest(AssertionClaims{
		ProviderID: "provider-main", Issuer: testProvider().Issuer, Audience: "knote-cli",
		Subject: "subject-process", TenantID: scope.TenantID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "nonce-process-shared",
	})
	replayCommands := startIdentityHelpers(t, root, barriers, now, "consume", string(digest), now.Add(time.Hour), 4)
	releaseIdentityHelpers(t, barriers, replayCommands)
	var replayWinners, replayRejections int
	for _, command := range replayCommands {
		output := waitIdentityHelper(t, command)
		switch {
		case strings.Contains(output, processHelperSuccess):
			replayWinners++
		case strings.Contains(output, processHelperReplay):
			replayRejections++
		default:
			t.Fatalf("unexpected replay helper output: %s", output)
		}
	}
	if replayWinners != 1 || replayRejections != len(replayCommands)-1 {
		t.Fatalf("cross-process replay outcomes winners=%d replays=%d", replayWinners, replayRejections)
	}

	userCommands := make([]*identityHelperCommand, 0, 6)
	startPath := filepath.Join(barriers, "upsert-start")
	for index := 1; index <= 6; index++ {
		value := "process-user-" + formatTestSequence(index)
		userCommands = append(userCommands, startIdentityHelper(
			t, root, now, "upsert", value, time.Time{},
			filepath.Join(barriers, "upsert-ready-"+strconv.Itoa(index)), startPath,
		))
	}
	releaseStartedIdentityHelpers(t, startPath, userCommands)
	for _, command := range userCommands {
		if output := waitIdentityHelper(t, command); !strings.Contains(output, processHelperSuccess) {
			t.Fatalf("unexpected upsert helper output: %s", output)
		}
	}

	restarted := openTestStore(t, root, clock)
	snapshot, err := restarted.Snapshot(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Users) != len(userCommands) || snapshot.Revision.Number != uint64(2+len(userCommands)) {
		t.Fatalf("cross-process restart users=%d revision=%d", len(snapshot.Users), snapshot.Revision.Number)
	}
	for index, user := range snapshot.Users {
		want := "process-user-" + formatTestSequence(index+1)
		if user.ExternalID != want || user.PrincipalID != want {
			t.Fatalf("cross-process user %d = %+v, want %q", index, user, want)
		}
	}
}

func TestIdentityStoreSubprocessHelper(t *testing.T) {
	mode := os.Getenv(processHelperModeEnv)
	if mode == "" {
		return
	}
	now, err := time.Parse(time.RFC3339Nano, os.Getenv(processHelperClockEnv))
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenLocalStore(os.Getenv(processHelperRootEnv), WithClock(ClockFunc(func() time.Time { return now })))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv(processHelperReadyEnv), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv(processHelperStartEnv)); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for process test barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}

	ctx := context.Background()
	scope := testScope("tenant-process")
	switch mode {
	case "consume":
		expiresAt, err := time.Parse(time.RFC3339Nano, os.Getenv(processHelperExpiresEnv))
		if err != nil {
			t.Fatal(err)
		}
		err = store.Consume(ctx, NonceUse{
			TenantID: scope.TenantID, Digest: ReplayDigest(os.Getenv(processHelperValueEnv)), ExpiresAt: expiresAt,
		})
		switch {
		case err == nil:
			fmt.Println(processHelperSuccess)
		case errors.Is(err, ErrReplayDetected):
			fmt.Println(processHelperReplay)
		default:
			t.Fatal(err)
		}
	case "upsert":
		value := os.Getenv(processHelperValueEnv)
		_, change, err := store.UpsertUser(ctx, scope, UserUpsert{
			ProviderID: "provider-main", ExternalID: value,
			ExternalSubjectID: value, PrincipalID: value, Active: true,
		})
		if err != nil || !change.Changed {
			t.Fatalf("process upsert changed=%v err=%v", change.Changed, err)
		}
		fmt.Println(processHelperSuccess)
	default:
		t.Fatalf("unsupported process helper mode %q", mode)
	}
}

type identityHelperCommand struct {
	command   *exec.Cmd
	output    *bytes.Buffer
	readyPath string
}

func startIdentityHelpers(
	t *testing.T,
	root string,
	barriers string,
	now time.Time,
	mode string,
	value string,
	expiresAt time.Time,
	count int,
) []*identityHelperCommand {
	t.Helper()
	startPath := filepath.Join(barriers, mode+"-start")
	commands := make([]*identityHelperCommand, 0, count)
	for index := 1; index <= count; index++ {
		commands = append(commands, startIdentityHelper(
			t, root, now, mode, value, expiresAt,
			filepath.Join(barriers, mode+"-ready-"+strconv.Itoa(index)), startPath,
		))
	}
	return commands
}

func startIdentityHelper(
	t *testing.T,
	root string,
	now time.Time,
	mode string,
	value string,
	expiresAt time.Time,
	readyPath string,
	startPath string,
) *identityHelperCommand {
	t.Helper()
	output := &bytes.Buffer{}
	command := exec.Command(os.Args[0], "-test.run=^TestIdentityStoreSubprocessHelper$", "-test.count=1")
	command.Env = append(os.Environ(),
		processHelperModeEnv+"="+mode,
		processHelperRootEnv+"="+root,
		processHelperClockEnv+"="+now.Format(time.RFC3339Nano),
		processHelperReadyEnv+"="+readyPath,
		processHelperStartEnv+"="+startPath,
		processHelperValueEnv+"="+value,
		processHelperExpiresEnv+"="+expiresAt.Format(time.RFC3339Nano),
	)
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	helper := &identityHelperCommand{command: command, output: output, readyPath: readyPath}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	})
	return helper
}

func releaseIdentityHelpers(t *testing.T, barriers string, commands []*identityHelperCommand) {
	t.Helper()
	releaseStartedIdentityHelpers(t, filepath.Join(barriers, "consume-start"), commands)
}

func releaseStartedIdentityHelpers(t *testing.T, startPath string, commands []*identityHelperCommand) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for _, command := range commands {
		for {
			if _, err := os.Stat(command.readyPath); err == nil {
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("process helper did not become ready: %s", command.output.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	if err := os.WriteFile(startPath, []byte("start"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitIdentityHelper(t *testing.T, helper *identityHelperCommand) string {
	t.Helper()
	if err := helper.command.Wait(); err != nil {
		t.Fatalf("identity process helper failed: %v\n%s", err, helper.output.String())
	}
	return helper.output.String()
}
