package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	einotool "github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"github.com/zzqDeco/knote/internal/knowledge/versioned"
	"github.com/zzqDeco/knote/internal/protocol"
	"github.com/zzqDeco/knote/internal/repository"
)

const (
	NameBuild    = "knote_build"
	NameQuery    = "knote_query"
	NameExplain  = "knote_explain"
	NameEval     = "knote_eval"
	NameDiff     = "knote_diff"
	NameVersions = "knote_versions"
	NameCommit   = "knote_commit"
	NameRelease  = "knote_release"
	NameCheckout = "knote_checkout"
)

func New(svc versioned.Service) []einotool.InvokableTool {
	return []einotool.InvokableTool{
		buildTool(svc),
		queryTool(svc),
		explainTool(svc),
		evalTool(svc),
		diffTool(svc),
		versionsTool(svc),
		commitTool(svc),
		releaseTool(svc),
		checkoutTool(svc),
	}
}

func ByName(svc versioned.Service) map[string]einotool.InvokableTool {
	out := make(map[string]einotool.InvokableTool)
	for _, candidate := range New(svc) {
		info, err := candidate.Info(context.Background())
		if err != nil {
			continue
		}
		out[info.Name] = candidate
	}
	return out
}

type runner func(context.Context, string) (any, error)

type invokable struct {
	info *schema.ToolInfo
	run  runner
}

var _ einotool.InvokableTool = (*invokable)(nil)

func (t *invokable) Info(context.Context) (*schema.ToolInfo, error) {
	return t.info, nil
}

func (t *invokable) InvokableRun(ctx context.Context, argumentsInJSON string, _ ...einotool.Option) (string, error) {
	result, err := t.run(ctx, argumentsInJSON)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("encode tool result: %w", err)
	}
	return string(data), nil
}

func buildTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameBuild, "Build the current knote knowledge artifacts by calling the configured KAG backend.", nil),
		run: func(ctx context.Context, args string) (any, error) {
			if err := decodeArgs(args, nil); err != nil {
				return nil, err
			}
			result, err := svc.Build(ctx)
			if err != nil {
				return nil, err
			}
			return buildResult{
				Manifest:     result.Manifest,
				Report:       result.Report,
				KAGData:      result.KAGData,
				AdapterError: result.AdapterError,
			}, nil
		},
	}
}

func queryTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameQuery, "Ask the current knote knowledge base a question.", params(map[string]*schema.ParameterInfo{
			"question": stringParam("Natural language question to answer.", true),
		})),
		run: func(ctx context.Context, args string) (any, error) {
			var req questionArgs
			if err := decodeArgs(args, &req); err != nil {
				return nil, err
			}
			if strings.TrimSpace(req.Question) == "" {
				return nil, fmt.Errorf("question is required")
			}
			answer, err := svc.Query(ctx, req.Question)
			if err != nil {
				return nil, err
			}
			return answerResult(answer), nil
		},
	}
}

func explainTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameExplain, "Explain an answer with KAG evidence for the current knote knowledge base.", params(map[string]*schema.ParameterInfo{
			"question": stringParam("Natural language question to explain.", true),
		})),
		run: func(ctx context.Context, args string) (any, error) {
			var req questionArgs
			if err := decodeArgs(args, &req); err != nil {
				return nil, err
			}
			if strings.TrimSpace(req.Question) == "" {
				return nil, fmt.Errorf("question is required")
			}
			answer, err := svc.Explain(ctx, req.Question)
			if err != nil {
				return nil, err
			}
			return answerResult(answer), nil
		},
	}
}

func evalTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameEval, "Run knote eval questions against the current knowledge version.", nil),
		run: func(ctx context.Context, args string) (any, error) {
			if err := decodeArgs(args, nil); err != nil {
				return nil, err
			}
			report, err := svc.Eval(ctx)
			if err != nil {
				return nil, err
			}
			return evalReportResult(report), nil
		},
	}
}

func diffTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameDiff, "Show the Git diff for the current knote knowledge workspace.", params(map[string]*schema.ParameterInfo{
			"ref": stringParam("Optional Git ref to diff against.", false),
		})),
		run: func(ctx context.Context, args string) (any, error) {
			var req diffArgs
			if err := decodeArgs(args, &req); err != nil {
				return nil, err
			}
			diff, err := svc.Diff(ctx, req.Ref)
			if err != nil {
				return nil, err
			}
			return map[string]string{"diff": diff}, nil
		},
	}
}

func versionsTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameVersions, "List recent Git-backed knote knowledge versions.", params(map[string]*schema.ParameterInfo{
			"limit": integerParam("Maximum number of versions to list. Defaults to 20.", false),
		})),
		run: func(ctx context.Context, args string) (any, error) {
			var req versionsArgs
			if err := decodeArgs(args, &req); err != nil {
				return nil, err
			}
			limit := req.Limit
			if limit <= 0 {
				limit = 20
			}
			versions, err := svc.Versions(ctx, limit)
			if err != nil {
				return nil, err
			}
			return versionsResult{Versions: versionResults(versions)}, nil
		},
	}
}

func commitTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameCommit, "Commit the current knote knowledge version.", params(map[string]*schema.ParameterInfo{
			"message": stringParam("Git commit message.", false),
		})),
		run: func(ctx context.Context, args string) (any, error) {
			var req commitArgs
			if err := decodeArgs(args, &req); err != nil {
				return nil, err
			}
			result, err := svc.Commit(ctx, req.Message)
			if err != nil {
				return nil, err
			}
			return commitResult{
				Hash:    result.Hash,
				Summary: result.Summary,
				Output:  result.Output,
			}, nil
		},
	}
}

func releaseTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameRelease, "Create a release tag for the current knote knowledge version.", params(map[string]*schema.ParameterInfo{
			"tag": stringParam("Release tag to create.", true),
		})),
		run: func(ctx context.Context, args string) (any, error) {
			var req releaseArgs
			if err := decodeArgs(args, &req); err != nil {
				return nil, err
			}
			if strings.TrimSpace(req.Tag) == "" {
				return nil, fmt.Errorf("tag is required")
			}
			if err := svc.Release(ctx, req.Tag); err != nil {
				return nil, err
			}
			return map[string]string{"tag": req.Tag}, nil
		},
	}
}

func checkoutTool(svc versioned.Service) einotool.InvokableTool {
	return &invokable{
		info: toolInfo(NameCheckout, "Checkout a Git ref for the knote knowledge workspace.", params(map[string]*schema.ParameterInfo{
			"ref":         stringParam("Git ref to checkout.", true),
			"allow_dirty": booleanParam("Allow checkout while the workspace is dirty.", false),
		})),
		run: func(ctx context.Context, args string) (any, error) {
			var req checkoutArgs
			if err := decodeArgs(args, &req); err != nil {
				return nil, err
			}
			if strings.TrimSpace(req.Ref) == "" {
				return nil, fmt.Errorf("ref is required")
			}
			opts := repository.CheckoutOptions{AllowDirty: req.AllowDirty}
			if err := svc.Checkout(ctx, req.Ref, opts); err != nil {
				return nil, err
			}
			return map[string]any{"ref": req.Ref, "allow_dirty": opts.AllowDirty}, nil
		},
	}
}

func toolInfo(name string, desc string, paramsOneOf *schema.ParamsOneOf) *schema.ToolInfo {
	return &schema.ToolInfo{
		Name:        name,
		Desc:        desc,
		ParamsOneOf: paramsOneOf,
	}
}

func params(items map[string]*schema.ParameterInfo) *schema.ParamsOneOf {
	return schema.NewParamsOneOfByParams(items)
}

func stringParam(desc string, required bool) *schema.ParameterInfo {
	return &schema.ParameterInfo{Type: schema.String, Desc: desc, Required: required}
}

func integerParam(desc string, required bool) *schema.ParameterInfo {
	return &schema.ParameterInfo{Type: schema.Integer, Desc: desc, Required: required}
}

func booleanParam(desc string, required bool) *schema.ParameterInfo {
	return &schema.ParameterInfo{Type: schema.Boolean, Desc: desc, Required: required}
}

func decodeArgs(argumentsInJSON string, dst any) error {
	text := strings.TrimSpace(argumentsInJSON)
	if text == "" {
		text = "{}"
	}
	if dst == nil {
		var ignored map[string]any
		dst = &ignored
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid tool arguments: %w", err)
	}
	var trailing struct{}
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("invalid tool arguments: multiple JSON values")
	}
	return nil
}

type questionArgs struct {
	Question string `json:"question"`
}

type diffArgs struct {
	Ref string `json:"ref"`
}

type versionsArgs struct {
	Limit int `json:"limit"`
}

type commitArgs struct {
	Message string `json:"message"`
}

type releaseArgs struct {
	Tag string `json:"tag"`
}

type checkoutArgs struct {
	Ref        string `json:"ref"`
	AllowDirty bool   `json:"allow_dirty"`
}

type buildResult struct {
	Manifest     protocol.ArtifactManifest `json:"manifest"`
	Report       string                    `json:"report,omitempty"`
	KAGData      map[string]any            `json:"kag_data,omitempty"`
	AdapterError string                    `json:"adapter_error,omitempty"`
}

type answerResult struct {
	Answer       string         `json:"answer"`
	Evidence     []string       `json:"evidence,omitempty"`
	Uncertainty  string         `json:"uncertainty,omitempty"`
	Mode         string         `json:"mode,omitempty"`
	Data         map[string]any `json:"data,omitempty"`
	AdapterError string         `json:"adapter_error,omitempty"`
}

type evalReportResult struct {
	Results        []repository.EvalResult `json:"results"`
	Total          int                     `json:"total"`
	AdapterErrors  int                     `json:"adapter_errors"`
	KnowledgeHash  string                  `json:"knowledge_hash,omitempty"`
	ReportMarkdown string                  `json:"report_markdown,omitempty"`
}

type versionsResult struct {
	Versions []versionResult `json:"versions"`
}

type versionResult struct {
	Hash         string   `json:"hash"`
	ShortHash    string   `json:"short_hash"`
	Subject      string   `json:"subject"`
	RelativeTime string   `json:"relative_time"`
	Tags         []string `json:"tags,omitempty"`
	Current      bool     `json:"current"`
}

type commitResult struct {
	Hash    string `json:"hash"`
	Summary string `json:"summary,omitempty"`
	Output  string `json:"output,omitempty"`
}

func versionResults(versions []repository.Version) []versionResult {
	out := make([]versionResult, 0, len(versions))
	for _, version := range versions {
		out = append(out, versionResult{
			Hash:         version.Hash,
			ShortHash:    version.ShortHash,
			Subject:      version.Subject,
			RelativeTime: version.RelativeTime,
			Tags:         append([]string(nil), version.Tags...),
			Current:      version.Current,
		})
	}
	return out
}
