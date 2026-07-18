package authz

import (
	"fmt"
	"sort"
)

const maxAgentTaskContextualTuples = 3

// AgentTaskScope carries request-local evidence for a protected read. The
// evidence is deliberately separate from the persisted authorization tuple
// snapshot: an expired assignment or revoked delegation is represented by an
// omitted contextual tuple and therefore evaluates to deny.
type AgentTaskScope struct {
	User                 string
	Agent                string
	Task                 string
	AuthorizationModelID string
	ContextualTuples     []Tuple
}

func validateAgentTaskScope(user, relation, object, modelID string, scope *AgentTaskScope) error {
	if scope == nil {
		if relation == RelationCanViewInTask {
			return fmt.Errorf("%w: %s is internal to scoped authorization requests", ErrInvalidRequest, RelationCanViewInTask)
		}
		return nil
	}
	if relation != RelationCanView {
		return fmt.Errorf("%w: agent/task scope requires relation %q", ErrInvalidRequest, RelationCanView)
	}
	objectRef, err := parseReference("scoped object", object, false)
	if err != nil {
		return err
	}
	if !isProtectedResourceType(objectRef.typeName) {
		return fmt.Errorf("%w: agent/task scope cannot authorize %s", ErrInvalidRequest, objectRef.typeName)
	}
	if err := validateConcreteReference("scope user", scope.User, TypeUser); err != nil {
		return err
	}
	if scope.User != user {
		return fmt.Errorf("%w: scope user %q does not match request user %q", ErrInvalidRequest, scope.User, user)
	}
	if err := validateConcreteReference("scope agent", scope.Agent, TypeAgent); err != nil {
		return err
	}
	if err := validateConcreteReference("scope task", scope.Task, TypeTask); err != nil {
		return err
	}
	if err := validateModelID(scope.AuthorizationModelID); err != nil {
		return err
	}
	if scope.AuthorizationModelID != modelID {
		return fmt.Errorf(
			"%w: scope model %q does not match request model %q",
			ErrModelMismatch,
			scope.AuthorizationModelID,
			modelID,
		)
	}
	if len(scope.ContextualTuples) > maxAgentTaskContextualTuples {
		return fmt.Errorf("%w: agent/task scope has too many contextual tuples", ErrInvalidRequest)
	}

	expected := map[Tuple]struct{}{
		{User: scope.User, Relation: RelationDelegate, Object: scope.Agent}: {},
		{User: scope.Agent, Relation: RelationAgent, Object: scope.Task}:    {},
		{User: scope.User, Relation: RelationAssignee, Object: scope.Task}:  {},
	}
	seen := make(map[Tuple]struct{}, len(scope.ContextualTuples))
	for index, tuple := range scope.ContextualTuples {
		if _, ok := expected[tuple]; !ok {
			return fmt.Errorf("%w: contextual tuple %d does not belong to the declared user/agent/task scope", ErrInvalidRequest, index)
		}
		if _, duplicate := seen[tuple]; duplicate {
			return fmt.Errorf("%w: contextual tuple %d is duplicated", ErrInvalidRequest, index)
		}
		seen[tuple] = struct{}{}
	}
	return nil
}

func validateConcreteReference(name, value, expectedType string) error {
	ref, err := parseReference(name, value, false)
	if err != nil {
		return err
	}
	if ref.typeName != expectedType || ref.id == "*" {
		return fmt.Errorf("%w: %s must be a concrete %s:<id>", ErrInvalidRequest, name, expectedType)
	}
	return nil
}

func isProtectedResourceType(typeName string) bool {
	switch typeName {
	case TypeKnowledgeBase, TypeDocument, TypeEntity, TypeClaim:
		return true
	default:
		return false
	}
}

func effectiveRelation(relation string, scope *AgentTaskScope) string {
	if scope != nil {
		return RelationCanViewInTask
	}
	return relation
}

func contextualTuples(user, object string, scope *AgentTaskScope) []Tuple {
	if scope == nil {
		return nil
	}
	tuples := make([]Tuple, 0, len(scope.ContextualTuples)+1)
	tuples = append(tuples, scope.ContextualTuples...)
	tuples = append(tuples, Tuple{
		User:     scope.Task,
		Relation: RelationActiveTask,
		Object:   object,
	})
	sort.Slice(tuples, func(i, j int) bool {
		return tupleLess(tuples[i], tuples[j])
	})
	return tuples
}
