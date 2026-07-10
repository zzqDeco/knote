package model_test

import (
	"context"
	"os"
	"sort"
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
		"group-membership-add":                     false,
		"group-membership-remove":                  false,
		"inherited-read-and-edit":                  false,
		"restricted-child-blocks-only-inheritance": false,
		"direct-share":                             false,
		"direct-share-revoke":                      false,
	}
	for _, testCase := range suite.Tests {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			required[testCase.Name] = true
			authorizer, err := authz.NewLocalAuthorizer(testModelID, testCase.Tuples)
			if err != nil {
				t.Fatalf("create local authorizer: %v", err)
			}
			for _, check := range testCase.Check {
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
