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

type Version struct {
	Hash         string   `json:"hash"`
	ShortHash    string   `json:"short_hash"`
	Subject      string   `json:"subject"`
	RelativeTime string   `json:"relative_time"`
	Tags         []string `json:"tags,omitempty"`
	Current      bool     `json:"current"`
}

var knowledgePaths = []string{".knote/config.yaml", "sources", "artifacts", "evals"}

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
		return s.workspaceDiff(ctx)
	}
	paths := existingKnowledgePaths(s.Workspace)
	if len(paths) == 0 {
		return "", nil
	}
	return s.git(ctx, append([]string{"diff", ref, "--"}, paths...)...)
}

func (s Store) Log(ctx context.Context) (string, error) {
	return s.git(ctx, "log", "--oneline", "--decorate", "-n", "20")
}

func (s Store) Versions(ctx context.Context, limit int) ([]Version, error) {
	if limit <= 0 {
		limit = 20
	}
	head, err := s.git(ctx, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	out, err := s.git(ctx, "log", fmt.Sprintf("-n%d", limit), "--format=%H%x1f%h%x1f%s%x1f%cr%x1f%D")
	if err != nil {
		return nil, err
	}
	head = strings.TrimSpace(head)
	var versions []Version
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\x1f")
		if len(parts) < 5 {
			continue
		}
		version := Version{
			Hash:         parts[0],
			ShortHash:    parts[1],
			Subject:      parts[2],
			RelativeTime: parts[3],
			Tags:         tagsFromDecoration(parts[4]),
			Current:      parts[0] == head,
		}
		versions = append(versions, version)
	}
	return versions, nil
}

func (s Store) Commit(ctx context.Context, message string) (string, error) {
	if strings.TrimSpace(message) == "" {
		message = "knowledge: build " + time.Now().UTC().Format("20060102T150405Z")
	}
	existing := existingKnowledgePaths(s.Workspace)
	if len(existing) == 0 {
		return "", fmt.Errorf("nothing to commit")
	}
	if _, err := s.git(ctx, append([]string{"add"}, existing...)...); err != nil {
		return "", err
	}
	if _, err := s.git(ctx, append([]string{"diff", "--cached", "--quiet", "--"}, existing...)...); err == nil {
		return "", fmt.Errorf("nothing to commit")
	}
	args := append([]string{"commit", "-m", message, "--"}, existing...)
	return s.git(ctx, args...)
}

func (s Store) Tag(ctx context.Context, tag string) (string, error) {
	if strings.TrimSpace(tag) == "" {
		return "", fmt.Errorf("tag is required")
	}
	if s.Dirty(ctx) {
		return "", fmt.Errorf("release requires a clean workspace")
	}
	return s.git(ctx, "tag", "-a", tag, "-m", "release: "+tag)
}

func (s Store) Checkout(ctx context.Context, ref string, allowDirty bool) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", fmt.Errorf("ref is required")
	}
	if !allowDirty && s.Dirty(ctx) {
		return "", fmt.Errorf("checkout requires confirmation because the workspace is dirty")
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

func (s Store) workspaceDiff(ctx context.Context) (string, error) {
	paths := existingKnowledgePaths(s.Workspace)
	if len(paths) == 0 {
		return "", nil
	}
	var parts []string
	unstaged, err := s.git(ctx, append([]string{"diff", "--"}, paths...)...)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(unstaged) != "" {
		parts = append(parts, strings.TrimRight(unstaged, "\n"))
	}
	staged, err := s.git(ctx, append([]string{"diff", "--cached", "--"}, paths...)...)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(staged) != "" {
		parts = append(parts, strings.TrimRight(staged, "\n"))
	}
	untracked, err := s.untrackedKnowledgeFiles(ctx)
	if err != nil {
		return "", err
	}
	if len(untracked) > 0 {
		parts = append(parts, "Untracked knote files:\n  "+strings.Join(untracked, "\n  "))
	}
	return strings.Join(parts, "\n\n"), nil
}

func (s Store) untrackedKnowledgeFiles(ctx context.Context) ([]string, error) {
	paths := existingKnowledgePaths(s.Workspace)
	if len(paths) == 0 {
		return nil, nil
	}
	out, err := s.git(ctx, append([]string{"ls-files", "--others", "--exclude-standard", "--"}, paths...)...)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "" {
			files = append(files, strings.TrimSpace(line))
		}
	}
	return files, nil
}

func existingKnowledgePaths(workspace string) []string {
	var existing []string
	for _, path := range knowledgePaths {
		if _, err := os.Stat(filepath.Join(workspace, path)); err == nil {
			existing = append(existing, path)
		}
	}
	return existing
}

func tagsFromDecoration(decoration string) []string {
	var tags []string
	for _, part := range strings.Split(decoration, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "tag: ") {
			tags = append(tags, strings.TrimPrefix(part, "tag: "))
		}
	}
	return tags
}
