package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"

	openfga "github.com/openfga/go-sdk"
	fgaclient "github.com/openfga/go-sdk/client"

	"github.com/zzqDeco/knote/internal/identity"
)

const (
	identityControlType     = "identity_control"
	identityTenantType      = "identity_tenant"
	identityControlObject   = identityControlType + ":membership"
	identityClaimUser       = identityControlType + ":claim"
	identityClaimRelation   = "claimed"
	identityTenantRelation  = "tenant"
	openFGAIdentityPageSize = int32(100)
	maxOpenFGAIdentityPages = 10000
)

var _ identity.MembershipPublicationBackend = (*OpenFGAAuthorizer)(nil)

// InspectMembershipState reads the complete remote identity-owned state with
// higher consistency. Group membership is the only identity-owned relation in
// the checked-in model; organization membership is deliberately ignored.
func (a *OpenFGAAuthorizer) InspectMembershipState(
	ctx context.Context,
	target identity.MembershipPublicationTarget,
) (identity.MembershipRemoteState, error) {
	if err := a.validateIdentityPublicationTarget(ctx, target); err != nil {
		return identity.MembershipRemoteState{}, err
	}
	callContext, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()

	control, err := a.readAllTuples(callContext, fgaclient.ClientReadRequest{
		Object: openfga.PtrString(identityControlObject),
	})
	if err != nil {
		return identity.MembershipRemoteState{}, err
	}
	membership, err := a.readAllTuples(callContext, fgaclient.ClientReadRequest{
		Relation: openfga.PtrString(RelationMember),
	})
	if err != nil {
		return identity.MembershipRemoteState{}, err
	}

	state := identity.MembershipRemoteState{}
	for _, tuple := range control {
		key := tuple.Key
		if key.Condition != nil || key.Object != identityControlObject {
			return identity.MembershipRemoteState{}, fmt.Errorf("%w: malformed identity control tuple", ErrMalformedResponse)
		}
		switch {
		case key.User == identityClaimUser && key.Relation == identityClaimRelation:
			if state.Claimed {
				return identity.MembershipRemoteState{}, fmt.Errorf("%w: duplicate identity claim tuple", ErrMalformedResponse)
			}
			state.Claimed = true
		case key.Relation == identityTenantRelation && strings.HasPrefix(key.User, identityTenantType+":"):
			tenantID := strings.TrimPrefix(key.User, identityTenantType+":")
			if tenantID == "" || strings.Contains(tenantID, "#") {
				return identity.MembershipRemoteState{}, fmt.Errorf("%w: malformed identity tenant binding", ErrMalformedResponse)
			}
			state.TenantIDs = append(state.TenantIDs, tenantID)
		default:
			return identity.MembershipRemoteState{}, fmt.Errorf("%w: unknown identity control tuple", ErrMalformedResponse)
		}
	}

	for _, tuple := range membership {
		key := tuple.Key
		if key.Relation != RelationMember || !strings.HasPrefix(key.Object, TypeGroup+":") {
			continue
		}
		if key.Condition != nil || !strings.HasPrefix(key.User, TypeUser+":") ||
			strings.Contains(key.User, "#") {
			return identity.MembershipRemoteState{}, fmt.Errorf("%w: malformed identity membership tuple", ErrMalformedResponse)
		}
		principalID := strings.TrimPrefix(key.User, TypeUser+":")
		groupID := strings.TrimPrefix(key.Object, TypeGroup+":")
		if principalID == "" || groupID == "" {
			return identity.MembershipRemoteState{}, fmt.Errorf("%w: malformed identity membership tuple", ErrMalformedResponse)
		}
		state.Members = append(state.Members, identity.Membership{
			TenantID: target.TenantID, PrincipalID: principalID, GroupID: groupID,
		})
	}
	sort.Strings(state.TenantIDs)
	for index := 1; index < len(state.TenantIDs); index++ {
		if state.TenantIDs[index] == state.TenantIDs[index-1] {
			return identity.MembershipRemoteState{}, fmt.Errorf("%w: duplicate tenant binding", ErrMalformedResponse)
		}
	}
	sort.Slice(state.Members, func(i, j int) bool {
		if state.Members[i].GroupID != state.Members[j].GroupID {
			return state.Members[i].GroupID < state.Members[j].GroupID
		}
		return state.Members[i].PrincipalID < state.Members[j].PrincipalID
	})
	for index := 1; index < len(state.Members); index++ {
		if state.Members[index] == state.Members[index-1] {
			return identity.MembershipRemoteState{}, fmt.Errorf("%w: duplicate identity membership", ErrMalformedResponse)
		}
	}
	if err := state.Validate(target); err != nil {
		return identity.MembershipRemoteState{}, fmt.Errorf("%w: invalid remote identity state", ErrMalformedResponse)
	}
	return state, nil
}

// ClaimMembershipStore uses the fixed claim tuple as a remote mutex. OpenFGA
// transactions are atomic, and duplicate writes are errors, so two tenant
// bindings cannot both win a concurrent first claim.
func (a *OpenFGAAuthorizer) ClaimMembershipStore(
	ctx context.Context,
	target identity.MembershipPublicationTarget,
) error {
	if err := a.validateIdentityPublicationTarget(ctx, target); err != nil {
		return err
	}
	callContext, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()
	writes := []fgaclient.ClientTupleKey{
		{User: identityClaimUser, Relation: identityClaimRelation, Object: identityControlObject},
		{User: identityTenantType + ":" + target.TenantID, Relation: identityTenantRelation, Object: identityControlObject},
	}
	response, err := a.client.Write(callContext).
		Body(fgaclient.ClientWriteRequest{Writes: writes}).
		Options(fgaclient.ClientWriteOptions{
			AuthorizationModelId: openfga.PtrString(target.AuthorizationModelID),
			StoreId:              openfga.PtrString(target.StoreID),
			Conflict: fgaclient.ClientWriteConflictOptions{
				OnDuplicateWrites: fgaclient.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_ERROR,
				OnMissingDeletes:  fgaclient.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE,
			},
		}).Execute()
	if err != nil {
		return classifyOpenFGAError(callContext, err)
	}
	if response == nil || len(response.Writes) != len(writes) {
		return fmt.Errorf("%w: identity claim response count mismatch", ErrIncompleteResponse)
	}
	for _, result := range response.Writes {
		if result.Status != fgaclient.SUCCESS || result.Error != nil {
			return fmt.Errorf("%w: identity claim transaction failed", ErrUnavailable)
		}
	}
	return nil
}

func (a *OpenFGAAuthorizer) ApplyMembershipChanges(
	ctx context.Context,
	request identity.MembershipWriteRequest,
) error {
	if err := a.validateIdentityPublicationTarget(ctx, request.Target); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return identity.ErrPublicationUnavailable
	}
	writes := identityMembershipTuples(request.Writes)
	deletes := identityMembershipTuples(request.Deletes)
	for deleteOffset, writeOffset := 0, 0; deleteOffset < len(deletes) || writeOffset < len(writes); {
		batch := TupleWriteRequest{
			StoreID: request.Target.StoreID, AuthorizationModelID: request.Target.AuthorizationModelID,
		}
		deleteEnd := min(deleteOffset+MaxTupleOperationsPerWrite, len(deletes))
		batch.Deletes = deletes[deleteOffset:deleteEnd]
		deleteOffset = deleteEnd
		remaining := MaxTupleOperationsPerWrite - len(batch.Deletes)
		writeEnd := min(writeOffset+remaining, len(writes))
		batch.Writes = writes[writeOffset:writeEnd]
		writeOffset = writeEnd
		if err := a.ApplyTupleChanges(ctx, batch); err != nil {
			return err
		}
	}
	return nil
}

func (a *OpenFGAAuthorizer) validateIdentityPublicationTarget(
	ctx context.Context,
	target identity.MembershipPublicationTarget,
) error {
	if a == nil || a.client == nil || ctx == nil {
		return fmt.Errorf("%w: OpenFGA identity publication is not initialized", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil || validateStoreID(target.StoreID) != nil ||
		validateModelID(target.AuthorizationModelID) != nil {
		return fmt.Errorf("%w: identity publication target is invalid", ErrInvalidRequest)
	}
	if target.StoreID != a.config.StoreID || target.AuthorizationModelID != a.config.AuthorizationModelID {
		return fmt.Errorf("%w: identity publication target differs from configured OpenFGA revision", ErrModelMismatch)
	}
	return nil
}

func (a *OpenFGAAuthorizer) readAllTuples(
	ctx context.Context,
	filter fgaclient.ClientReadRequest,
) ([]openfga.Tuple, error) {
	var tuples []openfga.Tuple
	continuation := ""
	seenTokens := make(map[string]struct{})
	for page := 0; page < maxOpenFGAIdentityPages; page++ {
		options := fgaclient.ClientReadOptions{
			PageSize:    openfga.PtrInt32(openFGAIdentityPageSize),
			StoreId:     openfga.PtrString(a.config.StoreID),
			Consistency: openfga.CONSISTENCYPREFERENCE_HIGHER_CONSISTENCY.Ptr(),
		}
		if continuation != "" {
			options.ContinuationToken = openfga.PtrString(continuation)
		}
		response, err := a.client.Read(ctx).Body(filter).Options(options).Execute()
		if err != nil {
			return nil, classifyOpenFGAError(ctx, err)
		}
		if response == nil {
			return nil, fmt.Errorf("%w: tuple read response is nil", ErrMalformedResponse)
		}
		tuples = append(tuples, response.Tuples...)
		continuation = response.ContinuationToken
		if continuation == "" {
			return tuples, nil
		}
		if _, duplicate := seenTokens[continuation]; duplicate {
			return nil, fmt.Errorf("%w: tuple read continuation token repeated", ErrMalformedResponse)
		}
		seenTokens[continuation] = struct{}{}
	}
	return nil, fmt.Errorf("%w: tuple read exceeded pagination bound", ErrIncompleteResponse)
}

func identityMembershipTuples(members []identity.Membership) []Tuple {
	tuples := make([]Tuple, len(members))
	for index, member := range members {
		tuples[index] = Tuple{
			User: TypeUser + ":" + member.PrincipalID, Relation: RelationMember,
			Object: TypeGroup + ":" + member.GroupID,
		}
	}
	return tuples
}
