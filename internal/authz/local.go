package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const (
	relationInheritedReader   = "inherited_reader"
	relationInheritedEditor   = "inherited_editor"
	relationUnscopedReader    = "unscoped_reader"
	relationUnscopedEditor    = "unscoped_editor"
	relationSourceReader      = "source_reader"
	relationSourceEditor      = "source_editor"
	relationSubjectReader     = "subject_reader"
	relationSubjectEditor     = "subject_editor"
	relationObjectReader      = "object_reader"
	relationObjectEditor      = "object_editor"
	relationEntitiesReader    = "entities_reader"
	relationEntitiesEditor    = "entities_editor"
	relationInheritableReader = "inheritable_reader"
	relationInheritableEditor = "inheritable_editor"
)

var singularClaimBindingRelations = [...]string{
	RelationSourceDocument,
	RelationSubject,
	RelationObject,
}

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
	case TypeEntity:
		switch t.Relation {
		case RelationOrganization:
			if !isDirectType(subject, TypeOrganization) {
				return invalidTuple(t)
			}
		case RelationSourceDocument:
			if !isDirectType(subject, TypeDocument) {
				return invalidTuple(t)
			}
		case RelationViewer, RelationEditor:
			if !(isDirectUser(subject) || isGroupMemberset(subject)) {
				return invalidTuple(t)
			}
		case RelationRestricted:
			if !isRestrictedWildcard(subject) {
				return invalidTuple(t)
			}
		default:
			return invalidTuple(t)
		}
	case TypeClaim:
		switch t.Relation {
		case RelationOrganization:
			if !isDirectType(subject, TypeOrganization) {
				return invalidTuple(t)
			}
		case RelationSourceDocument:
			if !isDirectType(subject, TypeDocument) {
				return invalidTuple(t)
			}
		case RelationSubject, RelationObject:
			if !isDirectType(subject, TypeEntity) {
				return invalidTuple(t)
			}
		case RelationViewer, RelationEditor:
			if !(isDirectUser(subject) || isGroupMemberset(subject)) {
				return invalidTuple(t)
			}
		case RelationRestricted:
			if !isRestrictedWildcard(subject) {
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

// ValidateTuples validates a complete tuple snapshot before it is installed
// locally or written to OpenFGA. OpenFGA relations are set-valued, so the
// source/subject/object cardinality invariant must be enforced at write time.
func ValidateTuples(tuples []Tuple) error {
	unique := make(map[Tuple]struct{}, len(tuples))
	claimBindings := make(map[string]*claimBindingState)
	for _, tuple := range tuples {
		if err := tuple.Validate(); err != nil {
			return err
		}
		if _, ok := unique[tuple]; ok {
			continue
		}
		unique[tuple] = struct{}{}

		object, err := parseReference("tuple object", tuple.Object, false)
		if err != nil {
			return err
		}
		if object.typeName != TypeClaim {
			continue
		}
		state := claimBindings[tuple.Object]
		if state == nil {
			state = newClaimBindingState()
			claimBindings[tuple.Object] = state
		}
		if err := state.add(tuple); err != nil {
			return err
		}
	}

	objects := make([]string, 0, len(claimBindings))
	for object := range claimBindings {
		objects = append(objects, object)
	}
	sort.Strings(objects)
	for _, object := range objects {
		if err := claimBindings[object].validateComplete(object); err != nil {
			return err
		}
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

func isRestrictedWildcard(ref reference) bool {
	return ref.typeName == TypeUser && ref.id == "*" && ref.relation == ""
}

type claimBindingState struct {
	tupleCount int
	bindings   map[string]string
}

func newClaimBindingState() *claimBindingState {
	return &claimBindingState{bindings: make(map[string]string, len(singularClaimBindingRelations))}
}

func (s *claimBindingState) add(tuple Tuple) error {
	if isSingularClaimBindingRelation(tuple.Relation) {
		if existing, ok := s.bindings[tuple.Relation]; ok && existing != tuple.User {
			return invalidClaimBindingCardinality(tuple.Object, tuple.Relation)
		}
		s.bindings[tuple.Relation] = tuple.User
	}
	s.tupleCount++
	return nil
}

func (s *claimBindingState) remove(tuple Tuple) {
	if isSingularClaimBindingRelation(tuple.Relation) && s.bindings[tuple.Relation] == tuple.User {
		delete(s.bindings, tuple.Relation)
	}
	s.tupleCount--
}

func (s *claimBindingState) validateComplete(object string) error {
	for _, relation := range singularClaimBindingRelations {
		if _, ok := s.bindings[relation]; !ok {
			return invalidClaimBindingCardinality(object, relation)
		}
	}
	return nil
}

func isSingularClaimBindingRelation(relation string) bool {
	for _, candidate := range singularClaimBindingRelations {
		if relation == candidate {
			return true
		}
	}
	return false
}

func invalidClaimBindingCardinality(object, relation string) error {
	return fmt.Errorf("%w: claim %q must have exactly one %s binding", ErrInvalidRequest, object, relation)
}

type LocalAuthorizer struct {
	modelID       string
	mu            sync.RWMutex
	tuples        map[Tuple]struct{}
	claimBindings map[string]*claimBindingState
}

var _ Authorizer = (*LocalAuthorizer)(nil)

func NewLocalAuthorizer(modelID string, tuples []Tuple) (*LocalAuthorizer, error) {
	if err := validateModelID(modelID); err != nil {
		return nil, err
	}
	if err := ValidateTuples(tuples); err != nil {
		return nil, err
	}
	authorizer := &LocalAuthorizer{
		modelID:       modelID,
		tuples:        make(map[Tuple]struct{}, len(tuples)),
		claimBindings: make(map[string]*claimBindingState),
	}
	for _, tuple := range tuples {
		if err := authorizer.addTupleLocked(tuple); err != nil {
			return nil, err
		}
	}
	return authorizer, nil
}

func (a *LocalAuthorizer) AddTuple(tuple Tuple) error {
	if err := tuple.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.addTupleLocked(tuple)
}

func (a *LocalAuthorizer) RemoveTuple(tuple Tuple) error {
	if err := tuple.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.tuples[tuple]; !ok {
		return nil
	}
	delete(a.tuples, tuple)
	object, err := parseReference("tuple object", tuple.Object, false)
	if err != nil {
		return err
	}
	if object.typeName == TypeClaim {
		state := a.claimBindings[tuple.Object]
		state.remove(tuple)
		if state.tupleCount == 0 {
			delete(a.claimBindings, tuple.Object)
		}
	}
	return nil
}

func (a *LocalAuthorizer) addTupleLocked(tuple Tuple) error {
	if _, ok := a.tuples[tuple]; ok {
		return nil
	}
	object, err := parseReference("tuple object", tuple.Object, false)
	if err != nil {
		return err
	}
	if object.typeName == TypeClaim {
		state := a.claimBindings[tuple.Object]
		if state == nil {
			state = newClaimBindingState()
		}
		if err := state.add(tuple); err != nil {
			return err
		}
		a.claimBindings[tuple.Object] = state
	}
	a.tuples[tuple] = struct{}{}
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
	allowed, err := a.evaluateLocked(request.User, request.Relation, request.Object, newEvaluationState(ctx))
	a.mu.RUnlock()
	if err != nil {
		return decision, err
	}
	if err := ctx.Err(); err != nil {
		return decision, contextFailure(err)
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
		allowed, err := a.evaluateLocked(check.User, check.Relation, check.Object, newEvaluationState(ctx))
		if err != nil {
			return denied, err
		}
		if err := ctx.Err(); err != nil {
			return denied, contextFailure(err)
		}
		decisions[index] = Decision{
			CorrelationID:        check.CorrelationID,
			Allowed:              allowed,
			AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	if err := ctx.Err(); err != nil {
		return denied, contextFailure(err)
	}
	return decisions, nil
}

type evaluationKey struct {
	user     string
	relation string
	object   string
}

type evaluationState struct {
	ctx      context.Context
	visiting map[evaluationKey]bool
}

func newEvaluationState(ctx context.Context) *evaluationState {
	return &evaluationState{ctx: ctx, visiting: make(map[evaluationKey]bool)}
}

func (s *evaluationState) checkContext() error {
	if err := s.ctx.Err(); err != nil {
		return contextFailure(err)
	}
	return nil
}

func (a *LocalAuthorizer) evaluateLocked(user, relation, object string, state *evaluationState) (bool, error) {
	if err := state.checkContext(); err != nil {
		return false, err
	}
	key := evaluationKey{user: user, relation: relation, object: object}
	if state.visiting[key] {
		return false, nil
	}
	state.visiting[key] = true
	defer delete(state.visiting, key)

	objectRef, err := parseReference("object", object, false)
	if err != nil {
		return false, err
	}
	switch objectRef.typeName {
	case TypeGroup:
		if relation != RelationMember {
			return false, unsupportedRelation(objectRef.typeName, relation)
		}
		return a.directLocked(user, relation, object, state)
	case TypeOrganization:
		if relation != RelationMember {
			return false, unsupportedRelation(objectRef.typeName, relation)
		}
		return a.directLocked(user, relation, object, state)
	case TypeKnowledgeBase:
		return a.evaluateKnowledgeBaseLocked(user, relation, object, state)
	case TypeDocument:
		return a.evaluateDocumentLocked(user, relation, object, state)
	case TypeEntity:
		return a.evaluateEntityLocked(user, relation, object, state)
	case TypeClaim:
		return a.evaluateClaimLocked(user, relation, object, state)
	default:
		return false, fmt.Errorf("%w: unsupported object type %q", ErrInvalidRequest, objectRef.typeName)
	}
}

func (a *LocalAuthorizer) evaluateKnowledgeBaseLocked(user, relation, object string, state *evaluationState) (bool, error) {
	switch relation {
	case RelationOrganization, RelationViewer, RelationEditor:
		return a.directLocked(user, relation, object, state)
	case relationUnscopedReader:
		viewer, err := a.directLocked(user, RelationViewer, object, state)
		if err != nil || viewer {
			return viewer, err
		}
		return a.directLocked(user, RelationEditor, object, state)
	case RelationCanView:
		return a.intersectOrganizationLocked(user, relationUnscopedReader, object, state)
	case RelationCanEdit:
		return a.intersectOrganizationLocked(user, RelationEditor, object, state)
	default:
		return false, unsupportedRelation(TypeKnowledgeBase, relation)
	}
}

func (a *LocalAuthorizer) evaluateDocumentLocked(user, relation, object string, state *evaluationState) (bool, error) {
	switch relation {
	case RelationOrganization, RelationParent, RelationViewer, RelationEditor, RelationRestricted:
		return a.directLocked(user, relation, object, state)
	case relationInheritedReader, relationInheritedEditor:
		restricted, err := a.directLocked(user, RelationRestricted, object, state)
		if err != nil || restricted {
			return false, err
		}
		parentRelation := RelationCanView
		if relation == relationInheritedEditor {
			parentRelation = RelationCanEdit
		}
		return a.memberOfRelatedObjectsLocked(user, RelationParent, parentRelation, object, state)
	case relationUnscopedReader:
		viewer, err := a.directLocked(user, RelationViewer, object, state)
		if err != nil || viewer {
			return viewer, err
		}
		editor, err := a.directLocked(user, RelationEditor, object, state)
		if err != nil || editor {
			return editor, err
		}
		return a.evaluateLocked(user, relationInheritedReader, object, state)
	case relationUnscopedEditor:
		editor, err := a.directLocked(user, RelationEditor, object, state)
		if err != nil || editor {
			return editor, err
		}
		return a.evaluateLocked(user, relationInheritedEditor, object, state)
	case RelationCanView:
		return a.intersectOrganizationLocked(user, relationUnscopedReader, object, state)
	case RelationCanEdit:
		return a.intersectOrganizationLocked(user, relationUnscopedEditor, object, state)
	default:
		return false, unsupportedRelation(TypeDocument, relation)
	}
}

func (a *LocalAuthorizer) evaluateEntityLocked(user, relation, object string, state *evaluationState) (bool, error) {
	switch relation {
	case RelationOrganization, RelationSourceDocument, RelationViewer, RelationEditor, RelationRestricted:
		return a.directLocked(user, relation, object, state)
	case relationInheritedReader, relationInheritedEditor:
		restricted, err := a.directLocked(user, RelationRestricted, object, state)
		if err != nil || restricted {
			return false, err
		}
		sourceRelation := RelationCanView
		if relation == relationInheritedEditor {
			sourceRelation = RelationCanEdit
		}
		return a.memberOfRelatedObjectsLocked(user, RelationSourceDocument, sourceRelation, object, state)
	case relationUnscopedReader:
		return a.directOrInheritedLocked(user, object, relationInheritedReader, state)
	case relationUnscopedEditor:
		return a.directOrInheritedLocked(user, object, relationInheritedEditor, state)
	case RelationCanView:
		return a.intersectOrganizationLocked(user, relationUnscopedReader, object, state)
	case RelationCanEdit:
		return a.intersectOrganizationLocked(user, relationUnscopedEditor, object, state)
	default:
		return false, unsupportedRelation(TypeEntity, relation)
	}
}

func (a *LocalAuthorizer) evaluateClaimLocked(user, relation, object string, state *evaluationState) (bool, error) {
	bindings, ok := a.claimBindings[object]
	if !ok {
		return false, nil
	}
	if err := bindings.validateComplete(object); err != nil {
		return false, err
	}
	switch relation {
	case RelationOrganization, RelationSourceDocument, RelationSubject, RelationObject,
		RelationViewer, RelationEditor, RelationRestricted:
		return a.directLocked(user, relation, object, state)
	case relationSourceReader:
		return a.memberOfRelatedObjectsLocked(user, RelationSourceDocument, RelationCanView, object, state)
	case relationSourceEditor:
		return a.memberOfRelatedObjectsLocked(user, RelationSourceDocument, RelationCanEdit, object, state)
	case relationSubjectReader:
		return a.memberOfRelatedObjectsLocked(user, RelationSubject, RelationCanView, object, state)
	case relationSubjectEditor:
		return a.memberOfRelatedObjectsLocked(user, RelationSubject, RelationCanEdit, object, state)
	case relationObjectReader:
		return a.memberOfRelatedObjectsLocked(user, RelationObject, RelationCanView, object, state)
	case relationObjectEditor:
		return a.memberOfRelatedObjectsLocked(user, RelationObject, RelationCanEdit, object, state)
	case relationEntitiesReader:
		return a.allComputedRelationsLocked(user, object, state, relationSubjectReader, relationObjectReader)
	case relationEntitiesEditor:
		return a.allComputedRelationsLocked(user, object, state, relationSubjectEditor, relationObjectEditor)
	case relationInheritableReader:
		return a.allComputedRelationsLocked(user, object, state, relationSourceReader, relationEntitiesReader)
	case relationInheritableEditor:
		return a.allComputedRelationsLocked(user, object, state, relationSourceEditor, relationEntitiesEditor)
	case relationInheritedReader, relationInheritedEditor:
		restricted, err := a.directLocked(user, RelationRestricted, object, state)
		if err != nil || restricted {
			return false, err
		}
		if relation == relationInheritedReader {
			return a.evaluateLocked(user, relationInheritableReader, object, state)
		}
		return a.evaluateLocked(user, relationInheritableEditor, object, state)
	case relationUnscopedReader:
		return a.directOrInheritedLocked(user, object, relationInheritedReader, state)
	case relationUnscopedEditor:
		return a.directOrInheritedLocked(user, object, relationInheritedEditor, state)
	case RelationCanView:
		return a.intersectOrganizationLocked(user, relationUnscopedReader, object, state)
	case RelationCanEdit:
		return a.intersectOrganizationLocked(user, relationUnscopedEditor, object, state)
	default:
		return false, unsupportedRelation(TypeClaim, relation)
	}
}

func (a *LocalAuthorizer) directOrInheritedLocked(user, object, inheritedRelation string, state *evaluationState) (bool, error) {
	viewerOrEditor := RelationEditor
	if inheritedRelation == relationInheritedReader {
		viewer, err := a.directLocked(user, RelationViewer, object, state)
		if err != nil || viewer {
			return viewer, err
		}
	}
	direct, err := a.directLocked(user, viewerOrEditor, object, state)
	if err != nil || direct {
		return direct, err
	}
	return a.evaluateLocked(user, inheritedRelation, object, state)
}

func (a *LocalAuthorizer) allComputedRelationsLocked(user, object string, state *evaluationState, relations ...string) (bool, error) {
	for _, relation := range relations {
		if err := state.checkContext(); err != nil {
			return false, err
		}
		allowed, err := a.evaluateLocked(user, relation, object, state)
		if err != nil || !allowed {
			return false, err
		}
	}
	return true, nil
}

func (a *LocalAuthorizer) intersectOrganizationLocked(user, relation, object string, state *evaluationState) (bool, error) {
	member, err := a.memberOfRelatedOrganizationsLocked(user, object, state)
	if err != nil || !member {
		return false, err
	}
	return a.evaluateLocked(user, relation, object, state)
}

func (a *LocalAuthorizer) memberOfRelatedOrganizationsLocked(user, object string, state *evaluationState) (bool, error) {
	return a.memberOfRelatedObjectsLocked(user, RelationOrganization, RelationMember, object, state)
}

func (a *LocalAuthorizer) memberOfRelatedObjectsLocked(user, tupleRelation, computedRelation, object string, state *evaluationState) (bool, error) {
	relatedObjects, err := a.relatedObjectsLocked(tupleRelation, object, state)
	if err != nil {
		return false, err
	}
	for _, related := range relatedObjects {
		if err := state.checkContext(); err != nil {
			return false, err
		}
		allowed, err := a.evaluateLocked(user, computedRelation, related, state)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

func (a *LocalAuthorizer) directLocked(user, relation, object string, state *evaluationState) (bool, error) {
	userRef, err := parseReference("user", user, true)
	if err != nil {
		return false, err
	}
	tuples, err := a.matchingTuplesLocked(relation, object, state)
	if err != nil {
		return false, err
	}
	for _, tuple := range tuples {
		if err := state.checkContext(); err != nil {
			return false, err
		}
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
			allowed, err := a.evaluateLocked(user, subject.relation, base, state)
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

func (a *LocalAuthorizer) matchingTuplesLocked(relation, object string, state *evaluationState) ([]Tuple, error) {
	var matches []Tuple
	for tuple := range a.tuples {
		if err := state.checkContext(); err != nil {
			return nil, err
		}
		if tuple.Relation == relation && tuple.Object == object {
			matches = append(matches, tuple)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].User < matches[j].User })
	if err := state.checkContext(); err != nil {
		return nil, err
	}
	return matches, nil
}

func (a *LocalAuthorizer) relatedObjectsLocked(relation, object string, state *evaluationState) ([]string, error) {
	tuples, err := a.matchingTuplesLocked(relation, object, state)
	if err != nil {
		return nil, err
	}
	related := make([]string, 0, len(tuples))
	for _, tuple := range tuples {
		if err := state.checkContext(); err != nil {
			return nil, err
		}
		related = append(related, tuple.User)
	}
	sort.Strings(related)
	if err := state.checkContext(); err != nil {
		return nil, err
	}
	return related, nil
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
