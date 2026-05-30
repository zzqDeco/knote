package gitstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Store struct {
	Workspace string
}

func (s Store) Branch(ctx context.Context) string {
	out, err := s.git(ctx, "branch", "--show-current")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (s Store) Dirty(ctx context.Context) bool {
	out, err := s.git(ctx, "status", "--porcelain")
	return err == nil && strings.TrimSpace(out) != ""
}

func (s Store) Status(ctx context.Context) (string, error) {
	return s.git(ctx, "status", "--short", "--branch")
}

func (s Store) Diff(ctx context.Context, ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return s.git(ctx, "diff", "--stat")
	}
	return s.git(ctx, "diff", "--stat", ref)
}

func (s Store) Log(ctx context.Context) (string, error) {
	return s.git(ctx, "log", "--oneline", "--decorate", "-n", "20")
}

func (s Store) Commit(ctx context.Context, message string) (string, error) {
	if strings.TrimSpace(message) == "" {
		message = "knowledge: build " + time.Now().UTC().Format("20060102T150405Z")
	}
	paths := []string{".knote/config.yaml", "sources", "artifacts", "evals"}
	var existing []string
	for _, path := range paths {
		if _, err := os.Stat(filepath.Join(s.Workspace, path)); err == nil {
			existing = append(existing, path)
		}
	}
	if len(existing) == 0 {
		return "", fmt.Errorf("nothing to commit")
	}
	if _, err := s.git(ctx, append([]string{"add"}, existing...)...); err != nil {
		return "", err
	}
	return s.git(ctx, "commit", "-m", message)
}

func (s Store) Tag(ctx context.Context, tag string) (string, error) {
	if strings.TrimSpace(tag) == "" {
		return "", fmt.Errorf("tag is required")
	}
	return s.git(ctx, "tag", "-a", tag, "-m", "release: "+tag)
}

func (s Store) Checkout(ctx context.Context, ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", fmt.Errorf("ref is required")
	}
	return s.git(ctx, "checkout", ref)
}

func (s Store) git(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = s.Workspace
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
