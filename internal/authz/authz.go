package authz

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	APITokenEnv = "KNOTE_OPENFGA_API_TOKEN"
	// MaxBatchChecks matches the pinned OpenFGA SDK's physical server batch size
	// so one accepted logical batch cannot be split into multiple HTTP RPCs.
	MaxBatchChecks = 50
)

const (
	TypeUser          = "user"
	TypeAgent         = "agent"
	TypeTask          = "task"
	TypeGroup         = "group"
	TypeOrganization  = "organization"
	TypeKnowledgeBase = "knowledge_base"
	TypeDocument      = "document"
	TypeEntity        = "entity"
	TypeClaim         = "claim"
)

const (
	RelationMember         = "member"
	RelationDelegate       = "delegate"
	RelationAssignee       = "assignee"
	RelationAgent          = "agent"
	RelationActiveTask     = "active_task"
	RelationCanViewInTask  = "can_view_in_task"
	RelationOrganization   = "organization"
	RelationParent         = "parent"
	RelationSourceDocument = "source_document"
	RelationSubject        = "subject"
	RelationObject         = "object"
	RelationViewer         = "viewer"
	RelationEditor         = "editor"
	RelationRestricted     = "restricted"
	RelationCanView        = protocol.EvidenceReadRelation
	RelationCanEdit        = "can_edit"
)

var (
	ErrInvalidRequest     = errors.New("invalid authorization request")
	ErrModelMismatch      = errors.New("authorization model mismatch")
	ErrTimeout            = errors.New("authorization request timed out")
	ErrUnavailable        = errors.New("authorization service unavailable")
	ErrMalformedResponse  = errors.New("malformed authorization response")
	ErrIncompleteResponse = errors.New("incomplete authorization response")
)

var (
	ulidPattern        = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	typePattern        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	relationPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	correlationPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,36}$`)
)

type Consistency string

const (
	ConsistencyMinimizeLatency   Consistency = "minimize_latency"
	ConsistencyHigherConsistency Consistency = "higher_consistency"
)

type Mode string

const (
	ModeLocal   Mode = "local"
	ModeOpenFGA Mode = "openfga"
)

// Config is safe to persist: credentials are deliberately absent and the
// OpenFGA API token is read only from APITokenEnv when the authorizer is built.
type Config struct {
	Mode                 Mode          `json:"mode" yaml:"mode"`
	AuthorizationModelID string        `json:"authorization_model_id" yaml:"authorization_model_id"`
	Endpoint             string        `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	StoreID              string        `json:"store_id,omitempty" yaml:"store_id,omitempty"`
	Timeout              time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	Consistency          Consistency   `json:"consistency,omitempty" yaml:"consistency,omitempty"`
}

func New(config Config, localTuples []Tuple) (Authorizer, error) {
	if config.Mode == "" {
		config.Mode = ModeLocal
	}
	if err := validateModelID(config.AuthorizationModelID); err != nil {
		return nil, err
	}
	switch config.Mode {
	case ModeLocal:
		return NewLocalAuthorizer(config.AuthorizationModelID, localTuples)
	case ModeOpenFGA:
		return NewOpenFGA(OpenFGAConfig{
			Endpoint: config.Endpoint, StoreID: config.StoreID,
			AuthorizationModelID: config.AuthorizationModelID,
			Timeout:              config.Timeout, Consistency: config.Consistency,
		})
	default:
		return nil, fmt.Errorf("%w: unsupported authorization mode %q", ErrInvalidRequest, config.Mode)
	}
}

func (c Consistency) validate(allowEmpty bool) error {
	if allowEmpty && c == "" {
		return nil
	}
	switch c {
	case ConsistencyMinimizeLatency, ConsistencyHigherConsistency:
		return nil
	default:
		return fmt.Errorf("%w: unsupported consistency %q", ErrInvalidRequest, c)
	}
}

type CheckRequest struct {
	User                 string
	Relation             string
	Object               string
	AuthorizationModelID string
	Consistency          Consistency
	AgentTaskScope       *AgentTaskScope
}

func (r CheckRequest) Validate() error {
	if err := validateModelID(r.AuthorizationModelID); err != nil {
		return err
	}
	if err := validatePrincipal("user", r.User); err != nil {
		return err
	}
	if err := validateRelation(r.Relation); err != nil {
		return err
	}
	if err := validateObject("object", r.Object); err != nil {
		return err
	}
	if err := validateAgentTaskScope(r.User, r.Relation, r.Object, r.AuthorizationModelID, r.AgentTaskScope); err != nil {
		return err
	}
	return r.Consistency.validate(true)
}

type BatchCheckItem struct {
	CorrelationID  string
	User           string
	Relation       string
	Object         string
	AgentTaskScope *AgentTaskScope
}

type BatchCheckRequest struct {
	AuthorizationModelID string
	Consistency          Consistency
	Checks               []BatchCheckItem
}

func (r BatchCheckRequest) Validate() error {
	if err := validateModelID(r.AuthorizationModelID); err != nil {
		return err
	}
	if err := r.Consistency.validate(true); err != nil {
		return err
	}
	if err := validateBatchSize(len(r.Checks)); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(r.Checks))
	for index, check := range r.Checks {
		if err := validateCorrelationID(check.CorrelationID); err != nil {
			return fmt.Errorf("check %d: %w", index, err)
		}
		if _, ok := seen[check.CorrelationID]; ok {
			return fmt.Errorf("%w: duplicate correlation_id %q", ErrInvalidRequest, check.CorrelationID)
		}
		seen[check.CorrelationID] = struct{}{}
		if err := validatePrincipal("user", check.User); err != nil {
			return fmt.Errorf("check %q: %w", check.CorrelationID, err)
		}
		if err := validateRelation(check.Relation); err != nil {
			return fmt.Errorf("check %q: %w", check.CorrelationID, err)
		}
		if err := validateObject("object", check.Object); err != nil {
			return fmt.Errorf("check %q: %w", check.CorrelationID, err)
		}
		if err := validateAgentTaskScope(check.User, check.Relation, check.Object, r.AuthorizationModelID, check.AgentTaskScope); err != nil {
			return fmt.Errorf("check %q: %w", check.CorrelationID, err)
		}
	}
	return nil
}

func validateCorrelationID(value string) error {
	if !correlationPattern.MatchString(value) {
		return fmt.Errorf("%w: correlation_id must contain only letters, numbers, or hyphens and be at most 36 characters", ErrInvalidRequest)
	}
	return nil
}

func validateBatchSize(size int) error {
	if size == 0 {
		return fmt.Errorf("%w: batch must contain at least one check", ErrInvalidRequest)
	}
	if size > MaxBatchChecks {
		return fmt.Errorf("%w: batch cannot contain more than %d checks", ErrInvalidRequest, MaxBatchChecks)
	}
	return nil
}

type Decision struct {
	CorrelationID        string
	Allowed              bool
	AuthorizationModelID string
}

type Checker interface {
	Check(context.Context, CheckRequest) (Decision, error)
}

type BatchChecker interface {
	BatchCheck(context.Context, BatchCheckRequest) ([]Decision, error)
}

type Authorizer interface {
	Checker
	BatchChecker
}

func deniedDecision(modelID, correlationID string) Decision {
	return Decision{
		CorrelationID:        correlationID,
		Allowed:              false,
		AuthorizationModelID: modelID,
	}
}

func deniedBatch(request BatchCheckRequest) []Decision {
	decisions := make([]Decision, len(request.Checks))
	for index, check := range request.Checks {
		decisions[index] = deniedDecision(request.AuthorizationModelID, check.CorrelationID)
	}
	return decisions
}

func contextFailure(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}

func validateModelID(value string) error {
	if !ulidPattern.MatchString(value) {
		return fmt.Errorf("%w: authorization_model_id must be a canonical ULID", ErrInvalidRequest)
	}
	return nil
}

func validateStoreID(value string) error {
	if !ulidPattern.MatchString(value) {
		return fmt.Errorf("%w: store_id must be a canonical ULID", ErrInvalidRequest)
	}
	return nil
}

func validateRelation(value string) error {
	if !relationPattern.MatchString(value) {
		return fmt.Errorf("%w: relation %q is invalid", ErrInvalidRequest, value)
	}
	return nil
}

func validateObject(name, value string) error {
	ref, err := parseReference(name, value, false)
	if err != nil {
		return err
	}
	if ref.id == "*" {
		return fmt.Errorf("%w: %s cannot be a wildcard", ErrInvalidRequest, name)
	}
	return nil
}

func validateSubject(name, value string) error {
	_, err := parseReference(name, value, true)
	return err
}

// ValidateConcreteUserID validates an opaque user ID before it is prefixed for
// an OpenFGA check request.
func ValidateConcreteUserID(value string) error {
	return validatePrincipal("user", TypeUser+":"+value)
}

func validatePrincipal(name, value string) error {
	ref, err := parseReference(name, value, false)
	if err != nil {
		return err
	}
	if ref.typeName != TypeUser || ref.id == "*" {
		return fmt.Errorf("%w: %s must be a concrete %s:<id>", ErrInvalidRequest, name, TypeUser)
	}
	return nil
}

type reference struct {
	typeName string
	id       string
	relation string
}

func parseReference(name, value string, allowUserset bool) (reference, error) {
	if value == "" || len(value) > 256 {
		return reference{}, fmt.Errorf("%w: %s is empty or too long", ErrInvalidRequest, name)
	}
	base, usersetRelation, hasUserset := strings.Cut(value, "#")
	if hasUserset {
		if !allowUserset || strings.Contains(usersetRelation, "#") {
			return reference{}, fmt.Errorf("%w: %s %q has an invalid userset", ErrInvalidRequest, name, value)
		}
		if err := validateRelation(usersetRelation); err != nil {
			return reference{}, err
		}
	}
	typeName, id, ok := strings.Cut(base, ":")
	if !ok || !typePattern.MatchString(typeName) || id == "" || strings.Contains(id, ":") {
		return reference{}, fmt.Errorf("%w: %s %q must be type:opaque-id", ErrInvalidRequest, name, value)
	}
	for _, r := range id {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '#' {
			return reference{}, fmt.Errorf("%w: %s %q contains invalid characters", ErrInvalidRequest, name, value)
		}
	}
	return reference{typeName: typeName, id: id, relation: usersetRelation}, nil
}

func validateToken(name, value string) error {
	if value == "" || len(value) > 128 {
		return fmt.Errorf("%w: %s is empty or too long", ErrInvalidRequest, name)
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains whitespace or control characters", ErrInvalidRequest, name)
		}
	}
	return nil
}
