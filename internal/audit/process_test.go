package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	auditProcessModeEnv  = "KNOTE_AUDIT_TEST_PROCESS_MODE"
	auditProcessRootEnv  = "KNOTE_AUDIT_TEST_PROCESS_ROOT"
	auditProcessReadyEnv = "KNOTE_AUDIT_TEST_PROCESS_READY"
	auditProcessStartEnv = "KNOTE_AUDIT_TEST_PROCESS_START"
	auditProcessIndexEnv = "KNOTE_AUDIT_TEST_PROCESS_INDEX"
	auditProcessSuccess  = "AUDIT_PROCESS_SUCCESS"
)

func TestStoreSerializesCrossProcessAppends(t *testing.T) {
	root := filepath.Join(t.TempDir(), "audit")
	barriers := t.TempDir()
	store := openAuditTestStore(t, root, allowAuditResidency)
	scope := auditTestScope("tenant-process")
	if _, err := store.Append(context.Background(), scope, auditTestEntry("record-seed", 0)); err != nil {
		t.Fatal(err)
	}

	const helpers = 6
	startPath := filepath.Join(barriers, "start")
	commands := make([]*auditHelperCommand, 0, helpers)
	for index := 1; index <= helpers; index++ {
		readyPath := filepath.Join(barriers, "ready-"+strconv.Itoa(index))
		commands = append(commands, startAuditHelper(t, root, readyPath, startPath, index))
	}
	waitForAuditHelpersReady(t, commands)
	if err := os.WriteFile(startPath, []byte("start"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(context.Background(), scope, auditTestEntry("record-parent", helpers+1)); err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if output := waitAuditHelper(t, command); !strings.Contains(output, auditProcessSuccess) {
			t.Fatalf("unexpected audit helper output: %s", output)
		}
	}

	reopened := openAuditTestStore(t, root, allowAuditResidency)
	if err := reopened.Verify(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	references, err := reopened.ListReferences(context.Background(), scope, allowAuditList)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != helpers+2 {
		t.Fatalf("cross-process record count = %d, want %d", len(references), helpers+2)
	}
	identifiers := make([]string, 0, len(references))
	for _, reference := range references {
		identifiers = append(identifiers, reference.RecordID)
	}
	sort.Strings(identifiers)
	want := []string{
		"record-parent", "record-process-01", "record-process-02", "record-process-03",
		"record-process-04", "record-process-05", "record-process-06", "record-seed",
	}
	if fmt.Sprint(identifiers) != fmt.Sprint(want) {
		t.Fatalf("cross-process record IDs = %v, want %v", identifiers, want)
	}
}

func TestAuditStoreSubprocessHelper(t *testing.T) {
	if os.Getenv(auditProcessModeEnv) == "" {
		return
	}
	index, err := strconv.Atoi(os.Getenv(auditProcessIndexEnv))
	if err != nil || index <= 0 {
		t.Fatalf("invalid process index %q", os.Getenv(auditProcessIndexEnv))
	}
	store, err := OpenStore(os.Getenv(auditProcessRootEnv), allowAuditResidency)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv(auditProcessReadyEnv), []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv(auditProcessStartEnv)); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for cross-process audit barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}
	entry := auditTestEntry(fmt.Sprintf("record-process-%02d", index), index)
	if _, err := store.Append(context.Background(), auditTestScope("tenant-process"), entry); err != nil {
		t.Fatal(err)
	}
	fmt.Println(auditProcessSuccess)
}

type auditHelperCommand struct {
	command   *exec.Cmd
	output    *bytes.Buffer
	readyPath string
}

func startAuditHelper(
	t *testing.T,
	root string,
	readyPath string,
	startPath string,
	index int,
) *auditHelperCommand {
	t.Helper()
	output := &bytes.Buffer{}
	command := exec.Command(os.Args[0], "-test.run=^TestAuditStoreSubprocessHelper$", "-test.count=1")
	command.Env = append(os.Environ(),
		auditProcessModeEnv+"=append",
		auditProcessRootEnv+"="+root,
		auditProcessReadyEnv+"="+readyPath,
		auditProcessStartEnv+"="+startPath,
		auditProcessIndexEnv+"="+strconv.Itoa(index),
	)
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	helper := &auditHelperCommand{command: command, output: output, readyPath: readyPath}
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
	})
	return helper
}

func waitForAuditHelpersReady(t *testing.T, commands []*auditHelperCommand) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for _, command := range commands {
		for {
			if _, err := os.Stat(command.readyPath); err == nil {
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for audit helper: %s", command.output.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func waitAuditHelper(t *testing.T, helper *auditHelperCommand) string {
	t.Helper()
	if err := helper.command.Wait(); err != nil {
		t.Fatalf("audit helper failed: %v\n%s", err, helper.output.String())
	}
	return helper.output.String()
}
