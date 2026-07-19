package contract

import "time"

const (
	BatchCheckSampleCount        = 12
	BatchCheckBudgetMilliseconds = 100
	BatchCheckP99Budget          = BatchCheckBudgetMilliseconds * time.Millisecond

	ConnectorLagSampleCount        = 1
	ConnectorLagBudgetMilliseconds = 2000
	ConnectorLagMaxBudget          = ConnectorLagBudgetMilliseconds * time.Millisecond

	GovernanceSampleCount        = 2
	GovernanceBudgetMilliseconds = 1000
	GovernanceMaxBudget          = GovernanceBudgetMilliseconds * time.Millisecond

	ReconciliationSampleCount        = 1
	ReconciliationBudgetMilliseconds = 1000
	ReconciliationMaxBudget          = ReconciliationBudgetMilliseconds * time.Millisecond

	ReplaySampleCount        = 1
	ReplayBudgetMilliseconds = 3000
	ReplayMaxBudget          = ReplayBudgetMilliseconds * time.Millisecond

	RevocationSampleCount           = 128
	RevocationP95BudgetMilliseconds = 25
	RevocationP99BudgetMilliseconds = 100
	RevocationP95Budget             = RevocationP95BudgetMilliseconds * time.Millisecond
	RevocationP99Budget             = RevocationP99BudgetMilliseconds * time.Millisecond
)
