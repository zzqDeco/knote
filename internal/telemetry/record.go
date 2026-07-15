package telemetry

import (
	"errors"
	"fmt"
	"math"
)

var ErrInvalidRecord = errors.New("invalid telemetry record")

type ContractVersion uint8

const ContractVersion1 ContractVersion = 1

type MetricScope string

const (
	MetricScopeOperational MetricScope = "operational"
	MetricScopeCohort      MetricScope = "cohort"
)

type Event string

const (
	EventPermissionedQuery          Event = "permissioned_query"
	EventPermissionedReplay         Event = "permissioned_replay"
	EventPermissionedReconciliation Event = "permissioned_reconciliation"
	EventPermissionedRevocation     Event = "permissioned_revocation"
)

type Stage string

const (
	StageAuthorization  Stage = "authorization"
	StageDiscover       Stage = "discover"
	StageRetrieve       Stage = "retrieve"
	StageTraversal      Stage = "traversal"
	StageFinalFilter    Stage = "final_filter"
	StageEvidenceLoad   Stage = "evidence_load"
	StageGenerate       Stage = "generate"
	StageReplay         Stage = "replay"
	StageReconciliation Stage = "reconciliation"
	StageComplete       Stage = "complete"
)

type Outcome string

const (
	OutcomeOK                  Outcome = "ok"
	OutcomeAllowed             Outcome = "allowed"
	OutcomeDenied              Outcome = "denied"
	OutcomeNotFound            Outcome = "not_found"
	OutcomeProviderUnavailable Outcome = "provider_unavailable"
	OutcomeBackendUnavailable  Outcome = "backend_unavailable"
	OutcomeBudgetExceeded      Outcome = "budget_exceeded"
	OutcomeFailed              Outcome = "failed"
)

type BudgetName string

const (
	BudgetLocalHardLatency BudgetName = "local_hard_latency"
	BudgetSyntheticP99     BudgetName = "synthetic_p99"
	BudgetRevocationP95    BudgetName = "revocation_p95"
	BudgetRevocationP99    BudgetName = "revocation_p99"
	BudgetBatchCheckSize   BudgetName = "batch_check_size"
)

type BudgetResult string

const (
	BudgetPass BudgetResult = "pass"
	BudgetFail BudgetResult = "fail"
)

type Budget struct {
	Name   BudgetName   `json:"budget"`
	Result BudgetResult `json:"budget_result"`
}

type Counts struct {
	Samples                 uint64 `json:"sample_count"`
	Candidates              uint64 `json:"candidate_count"`
	Allowed                 uint64 `json:"allowed_count"`
	Dropped                 uint64 `json:"dropped_count"`
	RetrieveCandidates      uint64 `json:"retrieve_candidate_count"`
	EvidenceItems           uint64 `json:"evidence_item_count"`
	SelectedPaths           uint64 `json:"selected_path_count"`
	CompletePaths           uint64 `json:"complete_path_count"`
	UnauthorizedPaths       uint64 `json:"unauthorized_path_count"`
	UnauthorizedGenerators  uint64 `json:"unauthorized_generator_count"`
	BatchChecks             uint64 `json:"batch_check_count"`
	BatchCheckRPCs          uint64 `json:"batch_check_rpc_count"`
	FinalFilterCandidates   uint64 `json:"final_filter_candidate_count"`
	FinalFilterAllowed      uint64 `json:"final_filter_allowed_count"`
	FinalFilterDropped      uint64 `json:"final_filter_dropped_count"`
	ReconciliationAdditions uint64 `json:"reconciliation_add_count"`
	ReconciliationRemovals  uint64 `json:"reconciliation_remove_count"`
}

type Rates struct {
	RecallAt4                  float64 `json:"recall_at_4"`
	PrecisionAt4               float64 `json:"precision_at_4"`
	PositiveEmpty              float64 `json:"positive_empty_rate"`
	NegativeEmpty              float64 `json:"negative_empty_rate"`
	AuthorizedPathCompleteness float64 `json:"authorized_path_completeness"`
	HopAuthorizationDrop       float64 `json:"hop_authorization_drop_rate"`
	PostFilterDrop             float64 `json:"post_filter_drop_rate"`
}

type Durations struct {
	Elapsed           uint64 `json:"elapsed_ms"`
	Duration          uint64 `json:"duration_ms"`
	Latency           uint64 `json:"latency_ms"`
	BatchCheckLatency uint64 `json:"batch_check_latency_ms"`
	P95               uint64 `json:"p95_ms"`
	P99               uint64 `json:"p99_ms"`
	RevocationP95     uint64 `json:"revocation_p95_ms"`
	RevocationP99     uint64 `json:"revocation_p99_ms"`
}

type Record struct {
	ContractVersion ContractVersion `json:"contract_version"`
	MetricScope     MetricScope     `json:"metric_scope"`
	Event           Event           `json:"event"`
	Stage           Stage           `json:"stage"`
	Outcome         Outcome         `json:"outcome"`
	Budget
	Counts
	Rates
	Durations
}

func (r Record) Validate() error {
	if r.ContractVersion != ContractVersion1 || !validMetricScope(r.MetricScope) || !validEvent(r.Event) || !validStage(r.Stage) || !validOutcome(r.Outcome) || !validBudget(r.Budget) {
		return fmt.Errorf("%w: unsupported fixed value", ErrInvalidRecord)
	}
	for _, rate := range []float64{r.Rates.RecallAt4, r.Rates.PrecisionAt4, r.Rates.PositiveEmpty, r.Rates.NegativeEmpty, r.Rates.AuthorizedPathCompleteness, r.Rates.HopAuthorizationDrop, r.Rates.PostFilterDrop} {
		if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 || rate > 1 {
			return fmt.Errorf("%w: rate outside [0,1]", ErrInvalidRecord)
		}
	}
	if r.Counts.Candidates != r.Counts.Allowed+r.Counts.Dropped {
		return fmt.Errorf("%w: candidate counts do not balance", ErrInvalidRecord)
	}
	if r.Counts.FinalFilterCandidates != r.Counts.FinalFilterAllowed+r.Counts.FinalFilterDropped {
		return fmt.Errorf("%w: final-filter counts do not balance", ErrInvalidRecord)
	}
	if r.Counts.CompletePaths > r.Counts.SelectedPaths {
		return fmt.Errorf("%w: complete path count exceeds selected path count", ErrInvalidRecord)
	}
	if r.MetricScope == MetricScopeOperational && hasCohortOnlyMeasurement(r) {
		return fmt.Errorf("%w: cohort-only measurement in operational record", ErrInvalidRecord)
	}
	return nil
}

func validMetricScope(v MetricScope) bool {
	return v == MetricScopeOperational || v == MetricScopeCohort
}

func hasCohortOnlyMeasurement(r Record) bool {
	return r.Counts.UnauthorizedPaths != 0 || r.Counts.UnauthorizedGenerators != 0 ||
		r.Rates.RecallAt4 != 0 || r.Rates.PrecisionAt4 != 0 ||
		r.Rates.PositiveEmpty != 0 || r.Rates.NegativeEmpty != 0 ||
		r.Durations.P95 != 0 || r.Durations.P99 != 0 ||
		r.Durations.RevocationP95 != 0 || r.Durations.RevocationP99 != 0
}

func validEvent(v Event) bool {
	switch v {
	case EventPermissionedQuery, EventPermissionedReplay, EventPermissionedReconciliation, EventPermissionedRevocation:
		return true
	default:
		return false
	}
}

func validStage(v Stage) bool {
	switch v {
	case StageAuthorization, StageDiscover, StageRetrieve, StageTraversal, StageFinalFilter,
		StageEvidenceLoad, StageGenerate, StageReplay, StageReconciliation, StageComplete:
		return true
	default:
		return false
	}
}

func validOutcome(v Outcome) bool {
	switch v {
	case OutcomeOK, OutcomeAllowed, OutcomeDenied, OutcomeNotFound, OutcomeProviderUnavailable,
		OutcomeBackendUnavailable, OutcomeBudgetExceeded, OutcomeFailed:
		return true
	default:
		return false
	}
}

func validBudget(v Budget) bool {
	validName := false
	switch v.Name {
	case BudgetLocalHardLatency, BudgetSyntheticP99, BudgetRevocationP95, BudgetRevocationP99, BudgetBatchCheckSize:
		validName = true
	}
	return validName && (v.Result == BudgetPass || v.Result == BudgetFail)
}
