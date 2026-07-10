package authz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
)

type OpenFGAConfig struct {
	Endpoint             string
	StoreID              string
	AuthorizationModelID string
	Timeout              time.Duration
	Consistency          Consistency
}

type OpenFGAAuthorizer struct {
	config OpenFGAConfig
	client *fgaclient.OpenFgaClient
}

var _ Authorizer = (*OpenFGAAuthorizer)(nil)

func NewOpenFGA(config OpenFGAConfig) (*OpenFGAAuthorizer, error) {
	normalized, err := normalizeOpenFGAConfig(config)
	if err != nil {
		return nil, err
	}
	token, ok := os.LookupEnv(APITokenEnv)
	if !ok || token == "" || token != strings.TrimSpace(token) {
		return nil, fmt.Errorf("%w: %s must contain a non-empty API token", ErrInvalidRequest, APITokenEnv)
	}

	client, err := fgaclient.NewSdkClient(&fgaclient.ClientConfiguration{
		ApiUrl:               normalized.Endpoint,
		StoreId:              normalized.StoreID,
		AuthorizationModelId: normalized.AuthorizationModelID,
		Credentials: &credentials.Credentials{
			Method: credentials.CredentialsMethodApiToken,
			Config: &credentials.Config{ApiToken: token},
		},
		RetryParams: &openfga.RetryParams{MaxRetry: 0, MinWaitInMs: 1},
	})
	if err != nil {
		return nil, fmt.Errorf("configure OpenFGA client: %w", err)
	}
	return &OpenFGAAuthorizer{config: normalized, client: client}, nil
}

func normalizeOpenFGAConfig(config OpenFGAConfig) (OpenFGAConfig, error) {
	config.Endpoint = strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return OpenFGAConfig{}, fmt.Errorf("%w: endpoint must be an absolute HTTP(S) URL", ErrInvalidRequest)
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return OpenFGAConfig{}, fmt.Errorf("%w: endpoint must not contain credentials, query, or fragment", ErrInvalidRequest)
	}
	if endpoint.Scheme == "http" && !isLoopbackHost(endpoint.Hostname()) {
		return OpenFGAConfig{}, fmt.Errorf("%w: non-loopback OpenFGA endpoints must use HTTPS", ErrInvalidRequest)
	}
	if err := validateStoreID(config.StoreID); err != nil {
		return OpenFGAConfig{}, err
	}
	if err := validateModelID(config.AuthorizationModelID); err != nil {
		return OpenFGAConfig{}, err
	}
	if config.Timeout <= 0 {
		return OpenFGAConfig{}, fmt.Errorf("%w: timeout must be positive", ErrInvalidRequest)
	}
	if config.Consistency == "" {
		config.Consistency = ConsistencyHigherConsistency
	}
	if err := config.Consistency.validate(false); err != nil {
		return OpenFGAConfig{}, err
	}
	return config, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (a *OpenFGAAuthorizer) Check(ctx context.Context, request CheckRequest) (Decision, error) {
	decision := deniedDecision(request.AuthorizationModelID, "")
	if ctx == nil {
		return decision, fmt.Errorf("%w: context is nil", ErrInvalidRequest)
	}
	if err := request.Validate(); err != nil {
		return decision, err
	}
	if request.AuthorizationModelID != a.config.AuthorizationModelID {
		return decision, fmt.Errorf("%w: configured %q, requested %q", ErrModelMismatch, a.config.AuthorizationModelID, request.AuthorizationModelID)
	}
	consistency, err := a.consistency(request.Consistency)
	if err != nil {
		return decision, err
	}

	callContext, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()
	response, err := a.client.Check(callContext).
		Body(fgaclient.ClientCheckRequest{
			User:     request.User,
			Relation: request.Relation,
			Object:   request.Object,
		}).
		Options(fgaclient.ClientCheckOptions{
			AuthorizationModelId: &a.config.AuthorizationModelID,
			StoreId:              &a.config.StoreID,
			Consistency:          consistency,
		}).
		Execute()
	if err != nil {
		return decision, classifyOpenFGAError(callContext, err)
	}
	if response == nil {
		return decision, fmt.Errorf("%w: check response is nil", ErrMalformedResponse)
	}
	allowed, ok := response.GetAllowedOk()
	if !ok || allowed == nil {
		return decision, fmt.Errorf("%w: check response omitted allowed", ErrMalformedResponse)
	}
	decision.Allowed = *allowed
	return decision, nil
}

func (a *OpenFGAAuthorizer) BatchCheck(ctx context.Context, request BatchCheckRequest) ([]Decision, error) {
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
	if request.AuthorizationModelID != a.config.AuthorizationModelID {
		return denied, fmt.Errorf("%w: configured %q, requested %q", ErrModelMismatch, a.config.AuthorizationModelID, request.AuthorizationModelID)
	}
	consistency, err := a.consistency(request.Consistency)
	if err != nil {
		return denied, err
	}

	checks := make([]fgaclient.ClientBatchCheckItem, len(request.Checks))
	expected := make(map[string]struct{}, len(request.Checks))
	for index, check := range request.Checks {
		checks[index] = fgaclient.ClientBatchCheckItem{
			User:          check.User,
			Relation:      check.Relation,
			Object:        check.Object,
			CorrelationId: check.CorrelationID,
		}
		expected[check.CorrelationID] = struct{}{}
	}

	callContext, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()
	response, err := a.client.BatchCheck(callContext).
		Body(fgaclient.ClientBatchCheckRequest{Checks: checks}).
		Options(fgaclient.BatchCheckOptions{
			AuthorizationModelId: &a.config.AuthorizationModelID,
			StoreId:              &a.config.StoreID,
			Consistency:          consistency,
		}).
		Execute()
	if err != nil {
		return denied, classifyOpenFGAError(callContext, err)
	}
	if response == nil {
		return denied, fmt.Errorf("%w: batch response is nil", ErrMalformedResponse)
	}
	results, ok := response.GetResultOk()
	if !ok || results == nil {
		return denied, fmt.Errorf("%w: batch response omitted result", ErrIncompleteResponse)
	}
	if len(*results) != len(expected) {
		return denied, fmt.Errorf("%w: expected %d correlation IDs, received %d", ErrIncompleteResponse, len(expected), len(*results))
	}
	for correlationID := range *results {
		if _, ok := expected[correlationID]; !ok {
			return denied, fmt.Errorf("%w: unexpected correlation_id %q", ErrIncompleteResponse, correlationID)
		}
	}

	decisions := make([]Decision, len(request.Checks))
	for index, check := range request.Checks {
		result, ok := (*results)[check.CorrelationID]
		if !ok {
			return denied, fmt.Errorf("%w: missing correlation_id %q", ErrIncompleteResponse, check.CorrelationID)
		}
		if result.Error != nil {
			return denied, fmt.Errorf("%w: correlation_id %q contains an OpenFGA error", ErrIncompleteResponse, check.CorrelationID)
		}
		allowed, ok := result.GetAllowedOk()
		if !ok || allowed == nil {
			return denied, fmt.Errorf("%w: correlation_id %q omitted allowed", ErrMalformedResponse, check.CorrelationID)
		}
		decisions[index] = Decision{
			CorrelationID:        check.CorrelationID,
			Allowed:              *allowed,
			AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	return decisions, nil
}

func (a *OpenFGAAuthorizer) consistency(requested Consistency) (*openfga.ConsistencyPreference, error) {
	if requested == "" {
		requested = a.config.Consistency
	}
	if err := requested.validate(false); err != nil {
		return nil, err
	}
	value := openfga.CONSISTENCYPREFERENCE_HIGHER_CONSISTENCY
	if requested == ConsistencyMinimizeLatency {
		value = openfga.CONSISTENCYPREFERENCE_MINIMIZE_LATENCY
	}
	return &value, nil
}

func classifyOpenFGAError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return contextFailure(ctxErr)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return contextFailure(context.DeadlineExceeded)
	}
	return fmt.Errorf("%w: OpenFGA request failed: %v", ErrUnavailable, err)
}
