package authz

import (
	"context"
	"fmt"
	"sort"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"
)

// MaxTupleOperationsPerWrite keeps each OpenFGA transaction within the
// service's default tuple-write limit.
const MaxTupleOperationsPerWrite = 100

var _ TupleWriter = (*OpenFGAAuthorizer)(nil)

// ApplyTupleChanges writes deterministic transactional batches. Duplicate
// writes and missing deletes are ignored so retrying a partial reconciliation
// converges on the same tuple snapshot.
func (a *OpenFGAAuthorizer) ApplyTupleChanges(ctx context.Context, request TupleWriteRequest) error {
	if a == nil || a.client == nil || ctx == nil {
		return fmt.Errorf("%w: OpenFGA tuple writer is not initialized", ErrInvalidRequest)
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if request.StoreID != a.config.StoreID {
		return fmt.Errorf("%w: configured store %q, requested %q", ErrModelMismatch, a.config.StoreID, request.StoreID)
	}
	if request.AuthorizationModelID != a.config.AuthorizationModelID {
		return fmt.Errorf(
			"%w: configured %q, requested %q",
			ErrModelMismatch,
			a.config.AuthorizationModelID,
			request.AuthorizationModelID,
		)
	}
	if len(request.Writes) == 0 && len(request.Deletes) == 0 {
		return nil
	}
	batches, err := openFGAWriteBatches(request)
	if err != nil {
		return err
	}
	callContext, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()
	for _, batch := range batches {
		if err := a.applyOpenFGABatch(callContext, batch); err != nil {
			return err
		}
	}
	return nil
}

func (a *OpenFGAAuthorizer) applyOpenFGABatch(ctx context.Context, request TupleWriteRequest) error {
	writes := make([]fgaclient.ClientTupleKey, len(request.Writes))
	for index, tuple := range request.Writes {
		writes[index] = fgaclient.ClientTupleKey{
			User: tuple.User, Relation: tuple.Relation, Object: tuple.Object,
		}
	}
	deletes := make([]fgaclient.ClientTupleKeyWithoutCondition, len(request.Deletes))
	for index, tuple := range request.Deletes {
		deletes[index] = fgaclient.ClientTupleKeyWithoutCondition{
			User: tuple.User, Relation: tuple.Relation, Object: tuple.Object,
		}
	}
	response, err := a.client.Write(ctx).
		Body(fgaclient.ClientWriteRequest{Writes: writes, Deletes: deletes}).
		Options(fgaclient.ClientWriteOptions{
			AuthorizationModelId: openfga.PtrString(request.AuthorizationModelID),
			StoreId:              openfga.PtrString(request.StoreID),
			Conflict: fgaclient.ClientWriteConflictOptions{
				OnDuplicateWrites: fgaclient.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
				OnMissingDeletes:  fgaclient.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE,
			},
		}).
		Execute()
	if err != nil {
		return classifyOpenFGAError(ctx, err)
	}
	if response == nil {
		return fmt.Errorf("%w: tuple write response is nil", ErrMalformedResponse)
	}
	if len(response.Writes) != len(writes) || len(response.Deletes) != len(deletes) {
		return fmt.Errorf("%w: tuple write response count mismatch", ErrIncompleteResponse)
	}
	for _, result := range response.Writes {
		if result.Status != fgaclient.SUCCESS || result.Error != nil {
			return fmt.Errorf("%w: OpenFGA tuple write batch failed", ErrUnavailable)
		}
	}
	for _, result := range response.Deletes {
		if result.Status != fgaclient.SUCCESS || result.Error != nil {
			return fmt.Errorf("%w: OpenFGA tuple delete batch failed", ErrUnavailable)
		}
	}
	return nil
}

type openFGAObjectChanges struct {
	writes  []Tuple
	deletes []Tuple
}

func openFGAWriteBatches(request TupleWriteRequest) ([]TupleWriteRequest, error) {
	changesByObject := make(map[string]*openFGAObjectChanges)
	for _, tuple := range request.Deletes {
		changes := changesByObject[tuple.Object]
		if changes == nil {
			changes = &openFGAObjectChanges{}
			changesByObject[tuple.Object] = changes
		}
		changes.deletes = append(changes.deletes, tuple)
	}
	for _, tuple := range request.Writes {
		changes := changesByObject[tuple.Object]
		if changes == nil {
			changes = &openFGAObjectChanges{}
			changesByObject[tuple.Object] = changes
		}
		changes.writes = append(changes.writes, tuple)
	}
	objects := make([]string, 0, len(changesByObject))
	for object := range changesByObject {
		objects = append(objects, object)
	}
	sort.Strings(objects)

	batches := make([]TupleWriteRequest, 0)
	current := TupleWriteRequest{
		StoreID: request.StoreID, AuthorizationModelID: request.AuthorizationModelID,
	}
	flush := func() {
		if len(current.Writes) == 0 && len(current.Deletes) == 0 {
			return
		}
		batches = append(batches, current)
		current = TupleWriteRequest{
			StoreID: request.StoreID, AuthorizationModelID: request.AuthorizationModelID,
		}
	}
	for _, object := range objects {
		changes := changesByObject[object]
		operationCount := len(changes.writes) + len(changes.deletes)
		if operationCount > MaxTupleOperationsPerWrite {
			return nil, fmt.Errorf(
				"%w: authorization object requires %d tuple changes in one transaction",
				ErrInvalidRequest,
				operationCount,
			)
		}
		currentCount := len(current.Writes) + len(current.Deletes)
		if currentCount > 0 && currentCount+operationCount > MaxTupleOperationsPerWrite {
			flush()
		}
		current.Deletes = append(current.Deletes, changes.deletes...)
		current.Writes = append(current.Writes, changes.writes...)
	}
	flush()
	return batches, nil
}
