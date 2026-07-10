package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	relationInheritedReader = "inherited_reader"
	relationInheritedEditor = "inherited_editor"
	relationUnscopedReader  = "unscoped_reader"
	relationUnscopedEditor  = "unscoped_editor"
)

type Tuple struct {
	User     string `json:"user" yaml:"user"`
	Relation string `json:"relation" yaml:"relation"`
	Object   string `json:"object" yaml:"object"`
}

func (t Tuple) Validate() error {
	subject, err := parseReference("tuple user", t.User, true)
	if err != nil {
		return err
	}
	object, err := parseReference("tuple object", t.Object, false)
	if err != nil {
		return err
	}
	if object.id == "*" {
		return fmt.Errorf("%w: tuple object cannot be a wildcard", ErrInvalidRequest)
	}
	if err := validateRelation(t.Relation); err != nil {
		return err
	}

	switch object.typeName {
	case TypeGroup:
		if t.Relation != RelationMember || !isDirectUser(subject) {
			return invalidTuple(t)
		}
	case TypeOrganization:
		if t.Relation != RelationMember || !(isDirectUser(subject) || isGroupMemberset(subject)) {
			return invalidTuple(t)
		}
	case TypeKnowledgeBase:
		switch t.Relation {
		case RelationOrganization:
			if !isDirectType(subject, TypeOrganization) {
				return invalidTuple(t)
			}
		case RelationViewer, RelationEditor:
			if !(isDirectUser(subject) || isGroupMemberset(subject)) {
				return invalidTuple(t)
			}
		default:
			return invalidTuple(t)
		}
	case TypeDocument:
		switch t.Relation {
		case RelationOrganization:
			if !isDirectType(subject, TypeOrganization) {
				return invalidTuple(t)
			}
		case RelationParent:
			if !isDirectType(subject, TypeKnowledgeBase) {
				return invalidTuple(t)
			}
		case RelationViewer, RelationEditor:
			if !(isDirectUser(subject) || isGroupMemberset(subject)) {
				return invalidTuple(t)
			}
		case RelationRestricted:
			if subject.typeName != TypeUser || subject.id != "*" || subject.relation != "" {
				return invalidTuple(t)
			}
		default:
			return invalidTuple(t)
		}
	default:
		return invalidTuple(t)
	}
	return nil
}

func invalidTuple(tuple Tuple) error {
	return fmt.Errorf("%w: tuple %q#%s@%q is not valid for the knote model", ErrInvalidRequest, tuple.Object, tuple.Relation, tuple.User)
}

func isDirectUser(ref reference) bool {
	return isDirectType(ref, TypeUser) && ref.id != "*"
}

func isDirectType(ref reference, typeName string) bool {
	return ref.typeName == typeName && ref.id != "*" && ref.relation == ""
}

func isGroupMemberset(ref reference) bool {
	return ref.typeName == TypeGroup && ref.id != "*" && ref.relation == RelationMember
}

type LocalAuthorizer struct {
	modelID string
	mu      sync.RWMutex
	tuples  map[Tuple]struct{}
}

var _ Authorizer = (*LocalAuthorizer)(nil)

func NewLocalAuthorizer(modelID string, tuples []Tuple) (*LocalAuthorizer, error) {
	if err := validateModelID(modelID); err != nil {
		return nil, err
	}
	authorizer := &LocalAuthorizer{
		modelID: modelID,
		tuples:  make(map[Tuple]struct{}, len(tuples)),
	}
	for _, tuple := range tuples {
		if err := tuple.Validate(); err != nil {
			return nil, err
		}
		authorizer.tuples[tuple] = struct{}{}
	}
	return authorizer, nil
}

func (a *LocalAuthorizer) AddTuple(tuple Tuple) error {
	if err := tuple.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tuples[tuple] = struct{}{}
	return nil
}

func (a *LocalAuthorizer) RemoveTuple(tuple Tuple) error {
	if err := tuple.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tuples, tuple)
	return nil
}

func (a *LocalAuthorizer) Tuples() []Tuple {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sortedTuplesLocked()
}

func (a *LocalAuthorizer) Check(ctx context.Context, request CheckRequest) (Decision, error) {
	decision := deniedDecision(request.AuthorizationModelID, "")
	if ctx == nil {
		return decision, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := request.Validate(); err != nil {
		return decision, err
	}
	if request.AuthorizationModelID != a.modelID {
		return decision, fmt.Errorf("%w: configured %q, requested %q", ErrModelMismatch, a.modelID, request.AuthorizationModelID)
	}
	if err := ctx.Err(); err != nil {
		return decision, contextFailure(err)
	}

	a.mu.RLock()
	allowed, err := a.evaluateLocked(request.User, request.Relation, request.Object, make(map[evaluationKey]bool))
	a.mu.RUnlock()
	if err != nil {
		return decision, err
	}
	decision.Allowed = allowed
	return decision, nil
}

func (a *LocalAuthorizer) BatchCheck(ctx context.Context, request BatchCheckRequest) ([]Decision, error) {
	if err := validateBatchSize(len(request.Checks)); err != nil {
		return nil, err
	}
	denied := deniedBatch(request)
	if ctx == nil {
		return denied, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := request.Validate(); err != nil {
		return denied, err
	}
	if request.AuthorizationModelID != a.modelID {
		return denied, fmt.Errorf("%w: configured %q, requested %q", ErrModelMismatch, a.modelID, request.AuthorizationModelID)
	}
	if err := ctx.Err(); err != nil {
		return denied, contextFailure(err)
	}

	decisions := make([]Decision, len(request.Checks))
	a.mu.RLock()
	defer a.mu.RUnlock()
	for index, check := range request.Checks {
		if err := ctx.Err(); err != nil {
			return denied, contextFailure(err)
		}
		allowed, err := a.evaluateLocked(check.User, check.Relation, check.Object, make(map[evaluationKey]bool))
		if err != nil {
			return denied, err
		}
		decisions[index] = Decision{
			CorrelationID:        check.CorrelationID,
			Allowed:              allowed,
			AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	return decisions, nil
}

type evaluationKey struct {
	user     string
	relation string
	object   string
}

func (a *LocalAuthorizer) evaluateLocked(user, relation, object string, visiting map[evaluationKey]bool) (bool, error) {
	key := evaluationKey{user: user, relation: relation, object: object}
	if visiting[key] {
		return false, nil
	}
	visiting[key] = true
	defer delete(visiting, key)

	objectRef, err := parseReference("object", object, false)
	if err != nil {
		return false, err
	}
	switch objectRef.typeName {
	case TypeGroup:
		if relation != RelationMember {
			return false, unsupportedRelation(objectRef.typeName, relation)
		}
		return a.directLocked(user, relation, object, visiting)
	case TypeOrganization:
		if relation != RelationMember {
			return false, unsupportedRelation(objectRef.typeName, relation)
		}
		return a.directLocked(user, relation, object, visiting)
	case TypeKnowledgeBase:
		return a.evaluateKnowledgeBaseLocked(user, relation, object, visiting)
	case TypeDocument:
		return a.evaluateDocumentLocked(user, relation, object, visiting)
	default:
		return false, fmt.Errorf("%w: unsupported object type %q", ErrInvalidRequest, objectRef.typeName)
	}
}

func (a *LocalAuthorizer) evaluateKnowledgeBaseLocked(user, relation, object string, visiting map[evaluationKey]bool) (bool, error) {
	switch relation {
	case RelationOrganization, RelationViewer, RelationEditor:
		return a.directLocked(user, relation, object, visiting)
	case relationUnscopedReader:
		viewer, err := a.directLocked(user, RelationViewer, object, visiting)
		if err != nil || viewer {
			return viewer, err
		}
		return a.directLocked(user, RelationEditor, object, visiting)
	case RelationCanView:
		return a.intersectOrganizationLocked(user, relationUnscopedReader, object, visiting)
	case RelationCanEdit:
		return a.intersectOrganizationLocked(user, RelationEditor, object, visiting)
	default:
		return false, unsupportedRelation(TypeKnowledgeBase, relation)
	}
}

func (a *LocalAuthorizer) evaluateDocumentLocked(user, relation, object string, visiting map[evaluationKey]bool) (bool, error) {
	switch relation {
	case RelationOrganization, RelationParent, RelationViewer, RelationEditor, RelationRestricted:
		return a.directLocked(user, relation, object, visiting)
	case relationInheritedReader, relationInheritedEditor:
		restricted, err := a.directLocked(user, RelationRestricted, object, visiting)
		if err != nil || restricted {
			return false, err
		}
		parentRelation := RelationCanView
		if relation == relationInheritedEditor {
			parentRelation = RelationCanEdit
		}
		return a.memberOfRelatedObjectsLocked(user, RelationParent, parentRelation, object, visiting)
	case relationUnscopedReader:
		viewer, err := a.directLocked(user, RelationViewer, object, visiting)
		if err != nil || viewer {
			return viewer, err
		}
		editor, err := a.directLocked(user, RelationEditor, object, visiting)
		if err != nil || editor {
			return editor, err
		}
		return a.evaluateLocked(user, relationInheritedReader, object, visiting)
	case relationUnscopedEditor:
		editor, err := a.directLocked(user, RelationEditor, object, visiting)
		if err != nil || editor {
			return editor, err
		}
		return a.evaluateLocked(user, relationInheritedEditor, object, visiting)
	case RelationCanView:
		return a.intersectOrganizationLocked(user, relationUnscopedReader, object, visiting)
	case RelationCanEdit:
		return a.intersectOrganizationLocked(user, relationUnscopedEditor, object, visiting)
	default:
		return false, unsupportedRelation(TypeDocument, relation)
	}
}

func (a *LocalAuthorizer) intersectOrganizationLocked(user, relation, object string, visiting map[evaluationKey]bool) (bool, error) {
	member, err := a.memberOfRelatedOrganizationsLocked(user, object, visiting)
	if err != nil || !member {
		return false, err
	}
	return a.evaluateLocked(user, relation, object, visiting)
}

func (a *LocalAuthorizer) memberOfRelatedOrganizationsLocked(user, object string, visiting map[evaluationKey]bool) (bool, error) {
	return a.memberOfRelatedObjectsLocked(user, RelationOrganization, RelationMember, object, visiting)
}

func (a *LocalAuthorizer) memberOfRelatedObjectsLocked(user, tupleRelation, computedRelation, object string, visiting map[evaluationKey]bool) (bool, error) {
	for _, related := range a.relatedObjectsLocked(tupleRelation, object) {
		allowed, err := a.evaluateLocked(user, computedRelation, related, visiting)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func (a *LocalAuthorizer) directLocked(user, relation, object string, visiting map[evaluationKey]bool) (bool, error) {
	userRef, err := parseReference("user", user, true)
	if err != nil {
		return false, err
	}
	for _, tuple := range a.matchingTuplesLocked(relation, object) {
		if tuple.User == user {
			return true, nil
		}
		subject, err := parseReference("tuple user", tuple.User, true)
		if err != nil {
			return false, err
		}
		if subject.id == "*" && subject.relation == "" && subject.typeName == userRef.typeName {
			return true, nil
		}
		if subject.relation != "" {
			base := subject.typeName + ":" + subject.id
			allowed, err := a.evaluateLocked(user, subject.relation, base, visiting)
			if err != nil {
				return false, err
			}
			if allowed {
				return true, nil
			}
		}
	}
	return false, nil
}

func (a *LocalAuthorizer) matchingTuplesLocked(relation, object string) []Tuple {
	var matches []Tuple
	for tuple := range a.tuples {
		if tuple.Relation == relation && tuple.Object == object {
			matches = append(matches, tuple)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].User < matches[j].User })
	return matches
}

func (a *LocalAuthorizer) relatedObjectsLocked(relation, object string) []string {
	tuples := a.matchingTuplesLocked(relation, object)
	related := make([]string, 0, len(tuples))
	for _, tuple := range tuples {
		related = append(related, tuple.User)
	}
	sort.Strings(related)
	return related
}

func (a *LocalAuthorizer) sortedTuplesLocked() []Tuple {
	tuples := make([]Tuple, 0, len(a.tuples))
	for tuple := range a.tuples {
		tuples = append(tuples, tuple)
	}
	sort.Slice(tuples, func(i, j int) bool {
		left := strings.Join([]string{tuples[i].Object, tuples[i].Relation, tuples[i].User}, "\x00")
		right := strings.Join([]string{tuples[j].Object, tuples[j].Relation, tuples[j].User}, "\x00")
		return left < right
	})
	return tuples
}

func unsupportedRelation(objectType, relation string) error {
	return fmt.Errorf("%w: relation %q is not defined for %s", ErrInvalidRequest, relation, objectType)
}
