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
	"strings"
	"sync"
	"time"
)

const maxNDJSONLineBytes = 16 * 1024 * 1024

type Client struct {
	AdapterPath          string
	Workspace            string
	Host                 string
	Fake                 bool
	ConfigPath           string
	ProjectID            string
	Namespace            string
	Language             string
	RuntimeDir           string
	PermissionedProvider string
}

type Request struct {
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params,omitempty"`
}

type Response struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Code    string         `json:"code,omitempty"`
	Message string         `json:"message,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
	raw     json.RawMessage
}

type CorpusRecord struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Content    string `json:"content"`
	SourcePath string `json:"source_path"`
}

func (r *Response) UnmarshalJSON(data []byte) error {
	type responseWire struct {
		ID      string         `json:"id"`
		Type    string         `json:"type"`
		Code    string         `json:"code,omitempty"`
		Message string         `json:"message,omitempty"`
		Data    map[string]any `json:"data,omitempty"`
		Error   string         `json:"error,omitempty"`
	}
	var wire responseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*r = Response{
		ID: wire.ID, Type: wire.Type, Code: wire.Code, Message: wire.Message,
		Data: wire.Data, Error: wire.Error, raw: append(json.RawMessage(nil), data...),
	}
	return nil
}

type AdapterError struct {
	Code    string
	Message string
}

func (e *AdapterError) Error() string {
	return e.Message
}

func (e *AdapterError) Is(target error) bool {
	switch target {
	case ErrUnsupportedPrimitive:
		return e.Code == ErrorCodeUnsupportedPrimitive
	case ErrInvalidGraphBinding:
		return e.Code == ErrorCodeInvalidGraphBinding
	case ErrPrimitiveUnavailable:
		return e.Code == ErrorCodePrimitiveUnavailable
	case ErrInvalidPrimitiveResponse:
		return e.Code == ErrorCodeInvalidPrimitiveResponse
	default:
		return false
	}
}

func IsUnsupportedPrimitive(err error) bool {
	return errors.Is(err, ErrUnsupportedPrimitive)
}

func IsInvalidGraphBinding(err error) bool {
	return errors.Is(err, ErrInvalidGraphBinding)
}

func IsPrimitiveUnavailable(err error) bool {
	return errors.Is(err, ErrPrimitiveUnavailable)
}

func IsInvalidPrimitiveResponse(err error) bool {
	return errors.Is(err, ErrInvalidPrimitiveResponse)
}

type Backend interface {
	Health(ctx context.Context) (Response, error)
	Build(ctx context.Context) (Response, error)
	BuildInNamespace(ctx context.Context, namespace, idempotencyKey string) (Response, error)
	Query(ctx context.Context, query string) (Response, error)
	QueryInNamespace(ctx context.Context, namespace, query string) (Response, error)
	Explain(ctx context.Context, query string) (Response, error)
	ExplainInNamespace(ctx context.Context, namespace, query string) (Response, error)
}

func (c Client) Health(ctx context.Context) (Response, error) {
	return c.call(ctx, "kag.health", c.params(nil))
}

func (c Client) Build(ctx context.Context) (Response, error) {
	return c.call(ctx, "kag.build", c.params(nil))
}

// BuildInNamespace sends idempotency_key as a durable adapter request token.
// The adapter must return the same logical result when that token is replayed.
func (c Client) BuildInNamespace(ctx context.Context, namespace, idempotencyKey string) (Response, error) {
	return c.call(ctx, "kag.build", c.projectionParams(namespace, map[string]any{
		"idempotency_key": idempotencyKey,
	}))
}

// BuildInNamespaceWithCorpus pins the build to caller-prepared source bytes.
func (c Client) BuildInNamespaceWithCorpus(ctx context.Context, namespace, idempotencyKey string, corpus []CorpusRecord) (Response, error) {
	return c.call(ctx, "kag.build", c.projectionParams(namespace, map[string]any{
		"idempotency_key": idempotencyKey,
		"corpus":          append([]CorpusRecord(nil), corpus...),
	}))
}

func (c Client) Query(ctx context.Context, query string) (Response, error) {
	return c.call(ctx, "kag.query", c.params(map[string]any{"query": query}))
}

func (c Client) QueryInNamespace(ctx context.Context, namespace, query string) (Response, error) {
	return c.call(ctx, "kag.query", c.projectionParams(namespace, map[string]any{"query": query}))
}

func (c Client) Explain(ctx context.Context, query string) (Response, error) {
	return c.call(ctx, "kag.explain", c.params(map[string]any{"query": query}))
}

func (c Client) ExplainInNamespace(ctx context.Context, namespace, query string) (Response, error) {
	return c.call(ctx, "kag.explain", c.projectionParams(namespace, map[string]any{"query": query}))
}

func (c Client) projectionParams(namespace string, extra map[string]any) map[string]any {
	namespace = strings.TrimSpace(namespace)
	params := c.params(extra)
	params["namespace"] = namespace
	params["projection_isolated"] = true
	runtimeDir := strings.TrimSpace(c.RuntimeDir)
	if runtimeDir == "" {
		runtimeDir = filepath.Join(".knote", "kag-runtime")
	}
	params["runtime_dir"] = filepath.Join(runtimeDir, "projections", namespace)
	return params
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
	configureAdapterCommand(cmd)
	cmd.Cancel = func() error {
		return killAdapterCommand(cmd)
	}
	cmd.Dir = c.Workspace
	cmd.Env = os.Environ()
	if c.Fake {
		cmd.Env = replaceProcessEnv(cmd.Env, "KNOTE_KAG_FAKE", "1")
	}
	if provider := strings.TrimSpace(c.PermissionedProvider); provider != "" {
		cmd.Env = replaceProcessEnv(cmd.Env, "KNOTE_KAG_PERMISSIONED_PROVIDER", provider)
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
	scanner.Buffer(make([]byte, 64*1024), maxNDJSONLineBytes)
	for scanner.Scan() {
		var resp Response
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			_ = killAdapterCommand(cmd)
			_ = cmd.Wait()
			return Response{}, err
		}
		if resp.ID != req.ID {
			_ = killAdapterCommand(cmd)
			_ = cmd.Wait()
			return Response{}, fmt.Errorf("kag adapter response id %q does not match request %q", resp.ID, req.ID)
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
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, err
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return last, ctx.Err()
	}
	if last.Type == "error" {
		return last, &AdapterError{Code: last.Code, Message: last.Error}
	}
	if waitErr != nil {
		return last, fmt.Errorf("kag adapter failed: %w: %s", waitErr, stderr.String())
	}
	if last.ID == "" {
		return Response{}, fmt.Errorf("kag adapter returned no response: %s", stderr.String())
	}
	if last.Type != "result" {
		return last, fmt.Errorf("kag adapter ended without a result frame")
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
	executable, _ := os.Executable()
	wd, _ := os.Getwd()
	return resolveAdapterPath(c.AdapterPath, c.Workspace, wd, executable)
}

func resolveAdapterPath(adapterPath, workspace, wd, executable string) string {
	if filepath.IsAbs(adapterPath) {
		return adapterPath
	}
	if candidate := filepath.Join(workspace, adapterPath); fileExists(candidate) {
		return candidate
	}
	if executable != "" {
		if found, ok := findInParents(filepath.Dir(executable), adapterPath); ok {
			return found
		}
	}
	if wd != "" {
		if found, ok := findInParents(wd, adapterPath); ok {
			return found
		}
	}
	return filepath.Join(workspace, adapterPath)
}

func findInParents(dir, rel string) (string, bool) {
	for {
		candidate := filepath.Join(dir, rel)
		if fileExists(candidate) {
			return candidate, true
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return "", false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func replaceProcessEnv(env []string, key, value string) []string {
	prefix := key + "="
	updated := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			updated = append(updated, entry)
		}
	}
	return append(updated, prefix+value)
}
