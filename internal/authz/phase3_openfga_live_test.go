package authz

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	phase3contract "github.com/zzqDeco/knote/tests/phase3/contract"
)

const phase3OpenFGALiveEnv = "KNOTE_PHASE3_OPENFGA_LIVE"

func TestPhase3OpenFGALiveSmoke(t *testing.T) {
	if os.Getenv(phase3OpenFGALiveEnv) != "1" {
		t.Skip("set KNOTE_PHASE3_OPENFGA_LIVE=1 to run the disposable OpenFGA smoke")
	}

	endpoint := requiredPhase3OpenFGAEnv(t, "KNOTE_OPENFGA_ENDPOINT")
	storeID := requiredPhase3OpenFGAEnv(t, "KNOTE_OPENFGA_STORE_ID")
	modelID := requiredPhase3OpenFGAEnv(t, "KNOTE_OPENFGA_MODEL_ID")
	requiredPhase3OpenFGAEnv(t, APITokenEnv)

	authorizer, err := NewOpenFGA(OpenFGAConfig{
		Endpoint:             endpoint,
		StoreID:              storeID,
		AuthorizationModelID: modelID,
		Timeout:              5 * time.Second,
		Consistency:          ConsistencyHigherConsistency,
	})
	if err != nil {
		t.Fatalf("configure live OpenFGA authorizer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const (
		user         = "user:phase3-smoke"
		agent        = "agent:phase3-smoke"
		task         = "task:phase3-smoke"
		organization = "organization:phase3-smoke"
		document     = "document:phase3-smoke"
	)

	viewer := Tuple{User: user, Relation: RelationViewer, Object: document}
	if err := authorizer.ApplyTupleChanges(ctx, TupleWriteRequest{
		StoreID: storeID, AuthorizationModelID: modelID,
		Writes: []Tuple{
			{User: organization, Relation: RelationOrganization, Object: document},
			viewer,
			{User: user, Relation: RelationMember, Object: organization},
		},
	}); err != nil {
		t.Fatalf("seed live OpenFGA authorization state: %v", err)
	}

	completeScope := &AgentTaskScope{
		User: user, Agent: agent, Task: task, AuthorizationModelID: modelID,
		ContextualTuples: []Tuple{
			{User: user, Relation: RelationDelegate, Object: agent},
			{User: agent, Relation: RelationAgent, Object: task},
			{User: user, Relation: RelationAssignee, Object: task},
		},
	}
	incompleteScope := &AgentTaskScope{
		User: user, Agent: agent, Task: task, AuthorizationModelID: modelID,
		ContextualTuples: []Tuple{
			{User: user, Relation: RelationDelegate, Object: agent},
			{User: agent, Relation: RelationAgent, Object: task},
		},
	}

	decision, err := authorizer.Check(ctx, CheckRequest{
		User: user, Relation: RelationCanView, Object: document,
		AuthorizationModelID: modelID, Consistency: ConsistencyHigherConsistency,
		AgentTaskScope: completeScope,
	})
	if err != nil {
		t.Fatalf("live scoped Check failed: %v", err)
	}
	if !decision.Allowed {
		t.Fatal("live scoped Check denied complete user-agent-task evidence")
	}

	decisions, err := authorizer.BatchCheck(ctx, BatchCheckRequest{
		AuthorizationModelID: modelID,
		Consistency:          ConsistencyHigherConsistency,
		Checks: []BatchCheckItem{
			{
				CorrelationID: "complete-scope", User: user, Relation: RelationCanView,
				Object: document, AgentTaskScope: completeScope,
			},
			{
				CorrelationID: "missing-assignee", User: user, Relation: RelationCanView,
				Object: document, AgentTaskScope: incompleteScope,
			},
		},
	})
	if err != nil {
		t.Fatalf("live scoped BatchCheck failed: %v", err)
	}
	if len(decisions) != 2 || !decisions[0].Allowed || decisions[1].Allowed {
		t.Fatal("live BatchCheck did not enforce the complete user-agent-task intersection")
	}

	latencies := make([]time.Duration, 0, phase3contract.BatchCheckSampleCount)
	for sample := 0; sample < phase3contract.BatchCheckSampleCount; sample++ {
		started := time.Now()
		decisions, err = authorizer.BatchCheck(ctx, BatchCheckRequest{
			AuthorizationModelID: modelID,
			Consistency:          ConsistencyHigherConsistency,
			Checks: []BatchCheckItem{
				{
					CorrelationID: "complete-scope", User: user, Relation: RelationCanView,
					Object: document, AgentTaskScope: completeScope,
				},
				{
					CorrelationID: "missing-assignee", User: user, Relation: RelationCanView,
					Object: document, AgentTaskScope: incompleteScope,
				},
			},
		})
		elapsed := time.Since(started)
		if err != nil {
			t.Fatalf("live BatchCheck latency sample %d failed: %v", sample, err)
		}
		if len(decisions) != 2 || !decisions[0].Allowed || decisions[1].Allowed {
			t.Fatalf("live BatchCheck latency sample %d violated the scoped oracle", sample)
		}
		latencies = append(latencies, elapsed)
	}
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	p99Index := (99*len(latencies)+99)/100 - 1
	p99 := latencies[p99Index]
	if p99 > phase3contract.BatchCheckP99Budget {
		t.Fatalf(
			"live OpenFGA BatchCheck p99 %s exceeds %s across %d samples",
			p99,
			phase3contract.BatchCheckP99Budget,
			len(latencies),
		)
	}
	t.Logf(
		"live OpenFGA BatchCheck samples=%d p99=%s budget=%s",
		len(latencies),
		p99,
		phase3contract.BatchCheckP99Budget,
	)

	if err := authorizer.ApplyTupleChanges(ctx, TupleWriteRequest{
		StoreID: storeID, AuthorizationModelID: modelID, Deletes: []Tuple{viewer},
	}); err != nil {
		t.Fatalf("revoke live OpenFGA viewer grant: %v", err)
	}

	decision, err = authorizer.Check(ctx, CheckRequest{
		User: user, Relation: RelationCanView, Object: document,
		AuthorizationModelID: modelID, Consistency: ConsistencyHigherConsistency,
		AgentTaskScope: completeScope,
	})
	if err != nil {
		t.Fatalf("live post-revoke Check failed: %v", err)
	}
	if decision.Allowed {
		t.Fatal("live post-revoke Check allowed stale user-agent-task evidence")
	}
}

func requiredPhase3OpenFGAEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" || value != strings.TrimSpace(value) {
		t.Fatalf("%s must be set to a non-empty canonical value", name)
	}
	return value
}
