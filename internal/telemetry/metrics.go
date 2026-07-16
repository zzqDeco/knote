package telemetry

type Metric string

const (
	MetricRecallAt4                          Metric = "recall_at_4"
	MetricPrecisionAt4                       Metric = "precision_at_4"
	MetricPositiveEmptyRate                  Metric = "positive_empty_rate"
	MetricNegativeEmptyRate                  Metric = "negative_empty_rate"
	MetricUnauthorizedPathParticipation      Metric = "unauthorized_path_participation"
	MetricUnauthorizedGeneratorParticipation Metric = "unauthorized_generator_participation"
	MetricHopAuthorizationDropRate           Metric = "hop_authorization_drop_rate"
	MetricPostFilterDropRate                 Metric = "post_filter_drop_rate"
	MetricLatencyP95                         Metric = "latency_p95"
	MetricLatencyP99                         Metric = "latency_p99"
	MetricRevocationP95                      Metric = "revocation_p95"
	MetricRevocationP99                      Metric = "revocation_p99"
)
