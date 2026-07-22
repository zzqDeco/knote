package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/zzqDeco/knote/internal/repository"
)

type gitClient struct {
	workspace string
	run       func(context.Context, ...string) (string, error)
}

var knowledgePaths = []string{".knote/config.yaml", "sources", "artifacts", "evals"}
var runtimeOnlyPaths = []string{".knote/sessions", ".knote/cache", ".knote/checkpoints", ".knote/kag-runtime", ".knote/projections", ".knote/audit"}

func (c gitClient) Branch(ctx context.Context) (string, error) {
	out, err := c.git(ctx, "branch", "--show-current")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (c gitClient) Dirty(ctx context.Context) (bool, error) {
	out, err := c.git(ctx, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if runtimeOnlyStatusLine(line) {
			continue
		}
		return true, nil
	}
	return false, nil
}

func (c gitClient) Status(ctx context.Context) (string, error) {
	return c.git(ctx, "status", "--short", "--branch")
}

func (c gitClient) Diff(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return c.workspaceDiff(ctx)
	}
	resolved, err := c.resolveRevision(ctx, ref)
	if err != nil {
		return "", err
	}
	paths, err := c.committableKnowledgePaths(ctx)
	if err != nil {
		return "", err
	}
	if len(paths) == 0 {
		return "", nil
	}
	return c.git(ctx, append([]string{"diff", resolved, "--"}, paths...)...)
}

func (c gitClient) Versions(ctx context.Context, limit int) ([]repository.Version, error) {
	if limit <= 0 {
		limit = 20
	}
	head, err := c.git(ctx, "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}")
	if err != nil {
		unborn, unbornErr := c.unbornHead(ctx)
		if unbornErr != nil {
			return nil, errors.Join(err, unbornErr)
		}
		if unborn {
			return []repository.Version{}, nil
		}
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

func (c gitClient) unbornHead(ctx context.Context) (bool, error) {
	ref, err := c.git(ctx, "symbolic-ref", "-q", "HEAD")
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(ref) == "" {
		return false, nil
	}
	_, err = c.git(ctx, "show-ref", "--verify", "--quiet", "--", strings.TrimSpace(ref))
	if err == nil {
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return true, nil
	}
	return false, err
}

func (c gitClient) Commit(ctx context.Context, message string) (output string, resultErr error) {
	if strings.TrimSpace(message) == "" {
		message = "knowledge: build " + time.Now().UTC().Format("20060102T150405Z")
	}
	publicationLock, err := c.lockArtifactPublicationForCommit(ctx)
	if err != nil {
		return "", err
	}
	defer publicationLock.release()
	paths, err := c.committableKnowledgePaths(ctx)
	if err != nil {
		return "", err
	}
	unrelated, err := c.shelveUnrelatedStagedChanges(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := c.restoreStagedChanges(context.Background(), unrelated); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("restore unrelated staged changes: %w", err))
		}
	}()
	if err := New(c.workspace).pruneUnselectedArtifactBundles(ctx); err != nil {
		return "", err
	}
	if _, err := c.git(ctx, "rm", "-r", "--cached", "--ignore-unmatch", "--", "artifacts"); err != nil {
		return "", err
	}
	addPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "artifacts" {
			if _, err := os.Stat(filepath.Join(c.workspace, path)); errors.Is(err, os.ErrNotExist) {
				continue
			}
		}
		addPaths = append(addPaths, path)
	}
	if len(addPaths) > 0 {
		if _, err := c.git(ctx, append([]string{"add", "-A", "--"}, addPaths...)...); err != nil {
			return "", err
		}
	}
	if _, err := c.git(ctx, "diff", "--cached", "--quiet"); err == nil {
		return "", fmt.Errorf("nothing to commit")
	}
	return c.git(ctx, "commit", "-m", message)
}

func (c gitClient) lockArtifactPublicationForCommit(ctx context.Context) (*artifactPublicationLock, error) {
	artifactsDir := filepath.Join(c.workspace, "artifacts")
	bundlesDir := filepath.Join(artifactsDir, "bundles")
	if _, err := os.Lstat(bundlesDir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := validateArtifactBundleDirectory(artifactsDir); err != nil {
		return nil, err
	}
	if err := validateArtifactBundleDirectory(bundlesDir); err != nil {
		return nil, err
	}
	return acquireArtifactPublicationLock(ctx, artifactsDir)
}

type stagedIndexEntry struct {
	path   string
	mode   string
	object string
}

func (c gitClient) shelveUnrelatedStagedChanges(ctx context.Context) ([]stagedIndexEntry, error) {
	out, err := c.git(ctx, "diff", "--cached", "--name-status", "-z")
	if err != nil {
		return nil, err
	}
	stagedPaths, err := pathsFromStagedNameStatus(out)
	if err != nil {
		return nil, err
	}
	var entries []stagedIndexEntry
	var paths []string
	for _, path := range stagedPaths {
		if knowledgePath(path) {
			continue
		}
		entry := stagedIndexEntry{path: path}
		staged, err := c.git(ctx, "ls-files", "--stage", "--", path)
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(staged)
		if len(fields) >= 3 && fields[2] == "0" {
			entry.mode = fields[0]
			entry.object = fields[1]
		}
		entries = append(entries, entry)
		paths = append(paths, path)
	}
	if len(paths) > 0 {
		baseline, err := c.baselineIndexEntries(ctx, paths)
		if err != nil {
			return nil, err
		}
		if err := c.applyIndexEntries(ctx, baseline); err != nil {
			if restoreErr := c.applyIndexEntries(context.Background(), entries); restoreErr != nil {
				return nil, errors.Join(err, fmt.Errorf("restore unrelated staged changes: %w", restoreErr))
			}
			return nil, err
		}
	}
	return entries, nil
}

func (c gitClient) baselineIndexEntries(ctx context.Context, paths []string) ([]stagedIndexEntry, error) {
	headExists := true
	if _, err := c.git(ctx, "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"); err != nil {
		unborn, unbornErr := c.unbornHead(ctx)
		if unbornErr != nil {
			return nil, errors.Join(err, unbornErr)
		}
		if !unborn {
			return nil, err
		}
		headExists = false
	}
	entries := make([]stagedIndexEntry, 0, len(paths))
	for _, path := range paths {
		entry := stagedIndexEntry{path: path}
		if headExists {
			out, err := c.git(ctx, "ls-tree", "-z", "HEAD", "--", path)
			if err != nil {
				return nil, err
			}
			if out != "" {
				metadata, _, ok := strings.Cut(strings.TrimSuffix(out, "\x00"), "\t")
				fields := strings.Fields(metadata)
				if !ok || len(fields) != 3 {
					return nil, fmt.Errorf("parse HEAD index entry for %q", path)
				}
				if fields[0] != "040000" {
					entry.mode = fields[0]
					entry.object = fields[2]
				}
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func pathsFromStagedNameStatus(out string) ([]string, error) {
	fields := strings.Split(out, "\x00")
	paths := make([]string, 0, len(fields))
	for index := 0; index < len(fields); {
		status := fields[index]
		index++
		if status == "" {
			break
		}
		pathCount := 1
		if status[0] == 'R' || status[0] == 'C' {
			pathCount = 2
		}
		if index+pathCount > len(fields) {
			return nil, fmt.Errorf("parse staged Git status %q: missing path", status)
		}
		for _, path := range fields[index : index+pathCount] {
			if path == "" {
				return nil, fmt.Errorf("parse staged Git status %q: empty path", status)
			}
			paths = append(paths, path)
		}
		index += pathCount
	}
	sort.Strings(paths)
	return slices.Compact(paths), nil
}

func (c gitClient) restoreStagedChanges(ctx context.Context, entries []stagedIndexEntry) error {
	return c.applyIndexEntries(ctx, entries)
}

func (c gitClient) applyIndexEntries(ctx context.Context, entries []stagedIndexEntry) error {
	for _, entry := range entries {
		if entry.object != "" {
			continue
		}
		if _, err := c.git(ctx, "update-index", "--force-remove", "--", entry.path); err != nil {
			return err
		}
	}
	for _, entry := range entries {
		if entry.object == "" {
			continue
		}
		if _, err := c.git(ctx, "update-index", "--add", "--cacheinfo", entry.mode, entry.object, entry.path); err != nil {
			return err
		}
	}
	return nil
}

func knowledgePath(path string) bool {
	path = filepath.ToSlash(path)
	for _, prefix := range knowledgePaths {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func (c gitClient) Tag(ctx context.Context, tag string) error {
	if err := validateGitInput("tag", tag); err != nil {
		return err
	}
	dirty, err := c.Dirty(ctx)
	if err != nil {
		return fmt.Errorf("inspect workspace cleanliness: %w", err)
	}
	if dirty {
		return fmt.Errorf("release requires a clean workspace")
	}
	_, err = c.git(ctx, "tag", "-a", "-m", "release: "+tag, "--", tag)
	return err
}

func (c gitClient) Checkout(ctx context.Context, ref string, allowDirty bool) error {
	if err := validateGitInput("ref", ref); err != nil {
		return err
	}
	dirty, err := c.Dirty(ctx)
	if err != nil {
		return fmt.Errorf("inspect workspace cleanliness: %w", err)
	}
	if dirty && !allowDirty {
		return fmt.Errorf("checkout requires confirmation because the workspace is dirty")
	}
	_, err = c.git(ctx, "checkout", ref)
	return err
}

func (c gitClient) resolveRevision(ctx context.Context, ref string) (string, error) {
	if err := validateGitInput("ref", ref); err != nil {
		return "", err
	}
	out, err := c.git(ctx, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func validateGitInput(kind, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", kind)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain surrounding whitespace", kind)
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s must not begin with '-'", kind)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain control characters", kind)
		}
	}
	return nil
}

func (c gitClient) git(ctx context.Context, args ...string) (string, error) {
	if c.run != nil {
		return c.run(ctx, args...)
	}
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
	paths, err := c.committableKnowledgePaths(ctx)
	if err != nil {
		return "", err
	}
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

func (c gitClient) committableKnowledgePaths(ctx context.Context) ([]string, error) {
	var paths []string
	for _, path := range knowledgePaths {
		if path == "artifacts" {
			selected, protected, err := New(c.workspace).committableArtifactPaths(ctx)
			if err != nil {
				return nil, err
			}
			if protected {
				paths = append(paths, selected...)
				continue
			}
		}
		if _, err := os.Stat(filepath.Join(c.workspace, path)); err == nil {
			paths = append(paths, path)
			continue
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		if c.trackedPath(ctx, path) {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func (c gitClient) trackedPath(ctx context.Context, path string) bool {
	_, err := c.git(ctx, "ls-files", "--error-unmatch", "--", path)
	return err == nil
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
