package kag

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type Client struct {
	AdapterPath string
	Workspace   string
	Host        string
	Fake        bool
	ConfigPath  string
	ProjectID   string
	Namespace   string
	Language    string
	RuntimeDir  string
}

type Request struct {
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

type Response struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Message string         `json:"message,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
}

func (c Client) Health(ctx context.Context) (Response, error) {
	return c.call(ctx, "kag.health", c.params(nil))
}

func (c Client) Build(ctx context.Context) (Response, error) {
	return c.call(ctx, "kag.build", c.params(nil))
}

func (c Client) Query(ctx context.Context, query string) (Response, error) {
	return c.call(ctx, "kag.query", c.params(map[string]any{"query": query}))
}

func (c Client) Explain(ctx context.Context, query string) (Response, error) {
	return c.call(ctx, "kag.explain", c.params(map[string]any{"query": query}))
}

func (c Client) params(extra map[string]any) map[string]any {
	params := map[string]any{
		"workspace":   c.Workspace,
		"host":        c.Host,
		"config_path": c.ConfigPath,
		"project_id":  c.ProjectID,
		"namespace":   c.Namespace,
		"language":    c.Language,
		"runtime_dir": c.RuntimeDir,
	}
	for key, value := range extra {
		params[key] = value
	}
	return params
}

func (c Client) call(ctx context.Context, method string, params map[string]any) (Response, error) {
	path := c.resolveAdapterPath()
	req := Request{
		ID:     fmt.Sprintf("req_%d", time.Now().UnixNano()),
		Method: method,
		Params: params,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}

	cmd := exec.CommandContext(ctx, pythonBin(), path)
	cmd.Dir = c.Workspace
	cmd.Env = os.Environ()
	if c.Fake {
		cmd.Env = append(cmd.Env, "KNOTE_KAG_FAKE=1")
	}
	cmd.Stdin = bytes.NewReader(append(payload, '\n'))
	out, err := cmd.StdoutPipe()
	if err != nil {
		return Response{}, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return Response{}, err
	}

	var last Response
	var mu sync.Mutex
	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		var resp Response
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			_ = cmd.Wait()
			return Response{}, err
		}
		mu.Lock()
		last = resp
		mu.Unlock()
		if resp.Type == "result" || resp.Type == "error" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return Response{}, err
	}
	waitErr := cmd.Wait()
	if last.Type == "error" {
		return last, errors.New(last.Error)
	}
	if waitErr != nil {
		return last, fmt.Errorf("kag adapter failed: %w: %s", waitErr, stderr.String())
	}
	if last.ID == "" {
		return Response{}, fmt.Errorf("kag adapter returned no response: %s", stderr.String())
	}
	return last, nil
}

func pythonBin() string {
	if value := os.Getenv("KNOTE_PYTHON"); value != "" {
		return value
	}
	if _, err := os.Stat("/usr/bin/python3"); err == nil {
		return "/usr/bin/python3"
	}
	return "python3"
}

func (c Client) resolveAdapterPath() string {
	if filepath.IsAbs(c.AdapterPath) {
		return c.AdapterPath
	}
	if _, err := os.Stat(filepath.Join(c.Workspace, c.AdapterPath)); err == nil {
		return filepath.Join(c.Workspace, c.AdapterPath)
	}
	return filepath.Join(projectRootFallback(c.Workspace, c.AdapterPath), c.AdapterPath)
}

func projectRootFallback(workspace, rel string) string {
	dir, err := os.Getwd()
	if err != nil {
		return workspace
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return workspace
}
