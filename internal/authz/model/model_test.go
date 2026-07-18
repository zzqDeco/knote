package model_test

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zzqDeco/knote/internal/authz"
	"github.com/zzqDeco/knote/internal/authz/model"
)

const testModelID = "01GAHCE4YVKPQEKZQHT2R89MQV"

type modelTestSuite struct {
	ModelFile string          `yaml:"model_file"`
	Tests     []modelTestCase `yaml:"tests"`
}

func TestIdentityTenantBindingTypesAreIsolatedFromProtectedRelations(t *testing.T) {
	for _, definition := range []string{
		"type identity_tenant",
		"type identity_control",
		"define claimed: [identity_control]",
		"define tenant: [identity_tenant]",
	} {
		if !strings.Contains(model.AuthorizationModel, definition) {
			t.Fatalf("authorization model is missing %q", definition)
		}
	}
	protected := model.AuthorizationModel[strings.Index(model.AuthorizationModel, "type group"):]
	if strings.Contains(protected, "identity_control") || strings.Contains(protected, "identity_tenant") {
		t.Fatal("identity binding types participate in protected authorization relations")
	}
}

type modelTestCase struct {
	Name   string        `yaml:"name"`
	Tuples []authz.Tuple `yaml:"tuples"`
	Check  []modelCheck  `yaml:"check"`
}

type modelCheck struct {
	User       string          `yaml:"user"`
	Object     string          `yaml:"object"`
	Assertions map[string]bool `yaml:"assertions"`
}

func TestAuthorizationModelTruthTable(t *testing.T) {
	data, err := os.ReadFile("authorization.fga.yaml")
	if err != nil {
		t.Fatalf("read model tests: %v", err)
	}
	var suite modelTestSuite
	if err := yaml.Unmarshal(data, &suite); err != nil {
		t.Fatalf("parse model tests: %v", err)
	}
	source, err := os.ReadFile(suite.ModelFile)
	if err != nil {
		t.Fatalf("read referenced model: %v", err)
	}
	if string(source) != model.AuthorizationModel {
		t.Fatal("embedded authorization model differs from the tested model file")
	}

	required := map[string]bool{
		"cross-tenant-direct-share":                false,
		"identity-control-is-non-authorizing":      false,
		"group-membership-add":                     false,
		"group-membership-remove":                  false,
		"inherited-read-and-edit":                  false,
		"restricted-child-blocks-only-inheritance": false,
		"direct-share":                             false,
		"direct-share-revoke":                      false,
		"entity-claim-policy-oracle":               false,
	}
	for _, testCase := range suite.Tests {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			required[testCase.Name] = true
			testTuples := testCase.Tuples
			testChecks := testCase.Check
			if testCase.Name == "identity-control-is-non-authorizing" {
				testTuples = protectedTruthTuplesWithoutIdentityControl(t, testCase.Tuples)
				testChecks = protectedTruthChecksWithoutIdentityControl(t, testCase.Check)
			}
			if err := authz.ValidateTuples(testTuples); err != nil {
				t.Fatalf("OpenFGA tuple snapshot preflight: %v", err)
			}
			authorizer, err := authz.NewLocalAuthorizer(testModelID, testTuples)
			if err != nil {
				t.Fatalf("create local authorizer: %v", err)
			}
			for _, check := range testChecks {
				relations := make([]string, 0, len(check.Assertions))
				for relation := range check.Assertions {
					relations = append(relations, relation)
				}
				sort.Strings(relations)
				for _, relation := range relations {
					decision, err := authorizer.Check(context.Background(), authz.CheckRequest{
						User:                 check.User,
						Relation:             relation,
						Object:               check.Object,
						AuthorizationModelID: testModelID,
						Consistency:          authz.ConsistencyHigherConsistency,
					})
					if err != nil {
						t.Fatalf("check %s %s on %s: %v", check.User, relation, check.Object, err)
					}
					if decision.Allowed != check.Assertions[relation] {
						t.Fatalf("check %s %s on %s: got %t, want %t", check.User, relation, check.Object, decision.Allowed, check.Assertions[relation])
					}
				}
			}
		})
	}
	for name, covered := range required {
		if !covered {
			t.Errorf("required model scenario %q is missing", name)
		}
	}
}

// The binding tuples exist only in the OpenFGA model and its CLI truth suite.
// Production Tuple validation deliberately rejects them so generic catalog and
// reconciliation writers cannot mutate the remote identity claim. The local
// policy oracle therefore evaluates the protected half of this scenario after
// independently requiring the exact isolated control tuple fixture.
func protectedTruthTuplesWithoutIdentityControl(t *testing.T, tuples []authz.Tuple) []authz.Tuple {
	t.Helper()
	wantControl := map[authz.Tuple]bool{
		{User: "identity_control:claim", Relation: "claimed", Object: "identity_control:membership"}:     false,
		{User: "identity_tenant:tenant-acme", Relation: "tenant", Object: "identity_control:membership"}: false,
	}
	protected := make([]authz.Tuple, 0, len(tuples)-len(wantControl))
	for _, tuple := range tuples {
		if _, ok := wantControl[tuple]; ok {
			if wantControl[tuple] {
				t.Fatalf("duplicate identity control truth tuple: %+v", tuple)
			}
			wantControl[tuple] = true
			continue
		}
		if strings.HasPrefix(tuple.Object, "identity_control:") ||
			strings.HasPrefix(tuple.User, "identity_control:") ||
			strings.HasPrefix(tuple.User, "identity_tenant:") {
			t.Fatalf("unexpected identity control truth tuple: %+v", tuple)
		}
		protected = append(protected, tuple)
	}
	for tuple, present := range wantControl {
		if !present {
			t.Fatalf("identity control truth fixture is missing %+v", tuple)
		}
	}
	return protected
}

func protectedTruthChecksWithoutIdentityControl(t *testing.T, checks []modelCheck) []modelCheck {
	t.Helper()
	wantSubjects := map[string]bool{
		"identity_control:claim":      false,
		"identity_tenant:tenant-acme": false,
	}
	ordinary := make([]modelCheck, 0, len(checks)-len(wantSubjects))
	for _, check := range checks {
		if _, ok := wantSubjects[check.User]; !ok {
			ordinary = append(ordinary, check)
			continue
		}
		if wantSubjects[check.User] {
			t.Fatalf("duplicate identity control truth check for %q", check.User)
		}
		if check.Object != "document:protected" || len(check.Assertions) != 2 ||
			check.Assertions[authz.RelationCanView] || check.Assertions[authz.RelationCanEdit] {
			t.Fatalf("identity control truth check is not an exact protected-access deny: %+v", check)
		}
		if _, ok := check.Assertions[authz.RelationCanView]; !ok {
			t.Fatalf("identity control truth check is missing can_view: %+v", check)
		}
		if _, ok := check.Assertions[authz.RelationCanEdit]; !ok {
			t.Fatalf("identity control truth check is missing can_edit: %+v", check)
		}
		wantSubjects[check.User] = true
	}
	for subject, present := range wantSubjects {
		if !present {
			t.Fatalf("identity control truth fixture is missing deny checks for %q", subject)
		}
	}
	return ordinary
}

func TestOpenFGATupleSnapshotPreflightRejectsDuplicateClaimBindings(t *testing.T) {
	tests := []struct {
		name      string
		relation  string
		duplicate string
	}{
		{name: "source", relation: authz.RelationSourceDocument, duplicate: "document:stale"},
		{name: "subject", relation: authz.RelationSubject, duplicate: "entity:stale-subject"},
		{name: "object", relation: authz.RelationObject, duplicate: "entity:stale-object"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tuples := []authz.Tuple{
				{User: "organization:acme", Relation: authz.RelationOrganization, Object: "claim:edge"},
				{User: "document:current", Relation: authz.RelationSourceDocument, Object: "claim:edge"},
				{User: "entity:subject", Relation: authz.RelationSubject, Object: "claim:edge"},
				{User: "entity:object", Relation: authz.RelationObject, Object: "claim:edge"},
				{User: test.duplicate, Relation: test.relation, Object: "claim:edge"},
			}
			if err := authz.ValidateTuples(tuples); !errors.Is(err, authz.ErrInvalidRequest) {
				t.Fatalf("preflight error = %v, want %v", err, authz.ErrInvalidRequest)
			}
		})
	}
}
