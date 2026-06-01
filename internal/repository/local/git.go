package local

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zzqDeco/knote/internal/repository"
)

type gitClient struct {
	workspace string
}

var knowledgePaths = []string{".knote/config.yaml", "sources", "artifacts", "evals"}
var runtimeOnlyPaths = []string{".knote/sessions", ".knote/cache", ".knote/checkpoints", ".knote/kag-runtime"}

func (c gitClient) Branch(ctx context.Context) string {
	out, err := c.git(ctx, "branch", "--show-current")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (c gitClient) Dirty(ctx context.Context) bool {
	out, err := c.git(ctx, "status", "--porcelain")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if runtimeOnlyStatusLine(line) {
			continue
		}
		return true
	}
	return false
}

func (c gitClient) Status(ctx context.Context) (string, error) {
	return c.git(ctx, "status", "--short", "--branch")
}

func (c gitClient) Diff(ctx context.Context, ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return c.workspaceDiff(ctx)
	}
	paths := existingKnowledgePaths(c.workspace)
	if len(paths) == 0 {
		return "", nil
	}
	return c.git(ctx, append([]string{"diff", ref, "--"}, paths...)...)
}

func (c gitClient) Versions(ctx context.Context, limit int) ([]repository.Version, error) {
	if limit <= 0 {
		limit = 20
	}
	head, err := c.git(ctx, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	out, err := c.git(ctx, "log", fmt.Sprintf("-n%d", limit), "--format=%H%x1f%h%x1f%s%x1f%cr%x1f%D")
	if err != nil {
		return nil, err
	}
	head = strings.TrimSpace(head)
	var versions []repository.Version
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\x1f")
		if len(parts) < 5 {
			continue
		}
		versions = append(versions, repository.Version{
			Hash:         parts[0],
			ShortHash:    parts[1],
			Subject:      parts[2],
			RelativeTime: parts[3],
			Tags:         tagsFromDecoration(parts[4]),
			Current:      parts[0] == head,
		})
	}
	return versions, nil
}

func (c gitClient) Commit(ctx context.Context, message string) (string, error) {
	if strings.TrimSpace(message) == "" {
		message = "knowledge: build " + time.Now().UTC().Format("20060102T150405Z")
	}
	existing := existingKnowledgePaths(c.workspace)
	if len(existing) == 0 {
		return "", fmt.Errorf("nothing to commit")
	}
	if _, err := c.git(ctx, append([]string{"add"}, existing...)...); err != nil {
		return "", err
	}
	if _, err := c.git(ctx, append([]string{"diff", "--cached", "--quiet", "--"}, existing...)...); err == nil {
		return "", fmt.Errorf("nothing to commit")
	}
	args := append([]string{"commit", "-m", message, "--"}, existing...)
	return c.git(ctx, args...)
}

func (c gitClient) Tag(ctx context.Context, tag string) error {
	if strings.TrimSpace(tag) == "" {
		return fmt.Errorf("tag is required")
	}
	if c.Dirty(ctx) {
		return fmt.Errorf("release requires a clean workspace")
	}
	_, err := c.git(ctx, "tag", "-a", tag, "-m", "release: "+tag)
	return err
}

func (c gitClient) Checkout(ctx context.Context, ref string, allowDirty bool) error {
	if strings.TrimSpace(ref) == "" {
		return fmt.Errorf("ref is required")
	}
	if !allowDirty && c.Dirty(ctx) {
		return fmt.Errorf("checkout requires confirmation because the workspace is dirty")
	}
	_, err := c.git(ctx, "checkout", ref)
	return err
}

func (c gitClient) git(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = c.workspace
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func (c gitClient) workspaceDiff(ctx context.Context) (string, error) {
	paths := existingKnowledgePaths(c.workspace)
	if len(paths) == 0 {
		return "", nil
	}
	var parts []string
	unstaged, err := c.git(ctx, append([]string{"diff", "--"}, paths...)...)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(unstaged) != "" {
		parts = append(parts, strings.TrimRight(unstaged, "\n"))
	}
	staged, err := c.git(ctx, append([]string{"diff", "--cached", "--"}, paths...)...)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(staged) != "" {
		parts = append(parts, strings.TrimRight(staged, "\n"))
	}
	untracked, err := c.untrackedKnowledgeFiles(ctx)
	if err != nil {
		return "", err
	}
	if len(untracked) > 0 {
		parts = append(parts, "Untracked knote files:\n  "+strings.Join(untracked, "\n  "))
	}
	return strings.Join(parts, "\n\n"), nil
}

func (c gitClient) untrackedKnowledgeFiles(ctx context.Context) ([]string, error) {
	paths := existingKnowledgePaths(c.workspace)
	if len(paths) == 0 {
		return nil, nil
	}
	out, err := c.git(ctx, append([]string{"ls-files", "--others", "--exclude-standard", "--"}, paths...)...)
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

func runtimeOnlyStatusLine(line string) bool {
	if len(line) < 4 {
		return false
	}
	path := strings.TrimSpace(line[3:])
	for _, prefix := range runtimeOnlyPaths {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}
