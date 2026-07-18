package authz

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
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
	identityFenceUserPrefix = identityControlType + ":publication_v1_"
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

	membership, err := a.readAllTuples(callContext, fgaclient.ClientReadRequest{
		Relation: openfga.PtrString(RelationMember),
	})
	if err != nil {
		return identity.MembershipRemoteState{}, err
	}
	// Read the fence last. Any concurrent membership transaction advances the
	// fence atomically, so a subsequent CAS cannot act on an older tuple view.
	control, err := a.readAllTuples(callContext, fgaclient.ClientReadRequest{
		Object: openfga.PtrString(identityControlObject),
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
		case key.Relation == identityClaimRelation && strings.HasPrefix(key.User, identityFenceUserPrefix):
			if state.PublicationFence != nil {
				return identity.MembershipRemoteState{}, fmt.Errorf("%w: duplicate identity publication fence", ErrMalformedResponse)
			}
			fence, err := parseIdentityPublicationFence(key.User)
			if err != nil {
				return identity.MembershipRemoteState{}, fmt.Errorf("%w: malformed identity publication fence", ErrMalformedResponse)
			}
			state.PublicationFence = &fence
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
	fence identity.MembershipPublicationFence,
) error {
	if err := a.validateIdentityPublicationTarget(ctx, target); err != nil {
		return err
	}
	if fence.State != identity.MembershipPublicationFenceActive || fence.Validate() != nil {
		return fmt.Errorf("%w: initial identity publication fence is invalid", ErrInvalidRequest)
	}
	callContext, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()
	writes := []fgaclient.ClientTupleKey{
		{User: identityClaimUser, Relation: identityClaimRelation, Object: identityControlObject},
		{User: identityTenantType + ":" + target.TenantID, Relation: identityTenantRelation, Object: identityControlObject},
		identityFenceClientTuple(fence),
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
	current := request.ExpectedFence
	desiredActive := identity.MembershipPublicationFence{
		State: identity.MembershipPublicationFenceActive, IdentityWatermark: request.IdentityWatermark,
		ProjectionDigest: request.ProjectionDigest,
	}
	callContext, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()
	if current.State == identity.MembershipPublicationFenceActive &&
		current.IdentityWatermark == request.IdentityWatermark &&
		current.ProjectionDigest == request.ProjectionDigest {
		desiredActive.Attempt = current.Attempt
	} else {
		next, err := nextIdentityFenceAttempt(current, desiredActive)
		if err != nil {
			return err
		}
		if err := a.applyIdentityPublicationBatch(callContext, request.Target, current, next, nil, nil); err != nil {
			return err
		}
		current = next
	}

	const membershipOperationsPerBatch = MaxTupleOperationsPerWrite - 2
	for deleteOffset, writeOffset := 0, 0; deleteOffset < len(deletes) || writeOffset < len(writes); {
		deleteEnd := min(deleteOffset+membershipOperationsPerBatch, len(deletes))
		batchDeletes := deletes[deleteOffset:deleteEnd]
		deleteOffset = deleteEnd
		remaining := membershipOperationsPerBatch - len(batchDeletes)
		writeEnd := min(writeOffset+remaining, len(writes))
		batchWrites := writes[writeOffset:writeEnd]
		writeOffset = writeEnd
		next, err := nextIdentityFenceAttempt(current, desiredActive)
		if err != nil {
			return err
		}
		if err := a.applyIdentityPublicationBatch(
			callContext, request.Target, current, next, batchWrites, batchDeletes,
		); err != nil {
			return err
		}
		current = next
	}
	published := identity.MembershipPublicationFence{
		State: identity.MembershipPublicationFencePublished, IdentityWatermark: request.IdentityWatermark,
		ProjectionDigest: request.ProjectionDigest,
	}
	return a.applyIdentityPublicationBatch(callContext, request.Target, current, published, nil, nil)
}

func nextIdentityFenceAttempt(
	current identity.MembershipPublicationFence,
	template identity.MembershipPublicationFence,
) (identity.MembershipPublicationFence, error) {
	if current.Attempt == ^uint64(0) {
		return identity.MembershipPublicationFence{}, fmt.Errorf("%w: identity publication attempt overflow", ErrUnavailable)
	}
	template.Attempt = current.Attempt + 1
	if err := template.Validate(); err != nil {
		return identity.MembershipPublicationFence{}, fmt.Errorf("%w: identity publication fence is invalid", ErrInvalidRequest)
	}
	return template, nil
}

func (a *OpenFGAAuthorizer) applyIdentityPublicationBatch(
	ctx context.Context,
	target identity.MembershipPublicationTarget,
	current identity.MembershipPublicationFence,
	next identity.MembershipPublicationFence,
	membershipWrites []Tuple,
	membershipDeletes []Tuple,
) error {
	if current.Validate() != nil || next.Validate() != nil || current == next ||
		len(membershipWrites)+len(membershipDeletes)+2 > MaxTupleOperationsPerWrite {
		return fmt.Errorf("%w: identity publication transaction is invalid", ErrInvalidRequest)
	}
	writes := make([]fgaclient.ClientTupleKey, 0, len(membershipWrites)+1)
	writes = append(writes, identityFenceClientTuple(next))
	for _, tuple := range membershipWrites {
		writes = append(writes, fgaclient.ClientTupleKey{
			User: tuple.User, Relation: tuple.Relation, Object: tuple.Object,
		})
	}
	deletes := make([]fgaclient.ClientTupleKeyWithoutCondition, 0, len(membershipDeletes)+1)
	currentTuple := identityFenceTuple(current)
	deletes = append(deletes, fgaclient.ClientTupleKeyWithoutCondition{
		User: currentTuple.User, Relation: currentTuple.Relation, Object: currentTuple.Object,
	})
	for _, tuple := range membershipDeletes {
		deletes = append(deletes, fgaclient.ClientTupleKeyWithoutCondition{
			User: tuple.User, Relation: tuple.Relation, Object: tuple.Object,
		})
	}
	response, err := a.client.Write(ctx).
		Body(fgaclient.ClientWriteRequest{Writes: writes, Deletes: deletes}).
		Options(fgaclient.ClientWriteOptions{
			AuthorizationModelId: openfga.PtrString(target.AuthorizationModelID),
			StoreId:              openfga.PtrString(target.StoreID),
			Conflict: fgaclient.ClientWriteConflictOptions{
				OnDuplicateWrites: fgaclient.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_ERROR,
				OnMissingDeletes:  fgaclient.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_ERROR,
			},
		}).Execute()
	if err != nil {
		return classifyOpenFGAError(ctx, err)
	}
	if response == nil || len(response.Writes) != len(writes) || len(response.Deletes) != len(deletes) {
		return fmt.Errorf("%w: identity publication response count mismatch", ErrIncompleteResponse)
	}
	for _, result := range response.Writes {
		if result.Status != fgaclient.SUCCESS || result.Error != nil {
			return fmt.Errorf("%w: identity publication transaction failed", ErrUnavailable)
		}
	}
	for _, result := range response.Deletes {
		if result.Status != fgaclient.SUCCESS || result.Error != nil {
			return fmt.Errorf("%w: identity publication transaction failed", ErrUnavailable)
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

func identityFenceClientTuple(fence identity.MembershipPublicationFence) fgaclient.ClientTupleKey {
	tuple := identityFenceTuple(fence)
	return fgaclient.ClientTupleKey{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object}
}

func identityFenceTuple(fence identity.MembershipPublicationFence) Tuple {
	revision, _ := identityFenceWatermarkParts(fence.IdentityWatermark)
	state := "a"
	if fence.State == identity.MembershipPublicationFencePublished {
		state = "p"
	}
	parts := strings.Split(fence.IdentityWatermark, "_")
	watermarkDigest := ""
	if len(parts) == 3 {
		watermarkDigest = parts[2]
	}
	projectionDigest := strings.TrimPrefix(fence.ProjectionDigest, "sha256:")
	return Tuple{
		User: fmt.Sprintf(
			"%s%s_%020d_%020d_%s_%s",
			identityFenceUserPrefix, state, fence.Attempt, revision, watermarkDigest, projectionDigest,
		),
		Relation: identityClaimRelation,
		Object:   identityControlObject,
	}
}

func parseIdentityPublicationFence(user string) (identity.MembershipPublicationFence, error) {
	if !strings.HasPrefix(user, identityFenceUserPrefix) {
		return identity.MembershipPublicationFence{}, fmt.Errorf("identity publication fence prefix is invalid")
	}
	parts := strings.Split(strings.TrimPrefix(user, identityFenceUserPrefix), "_")
	if len(parts) != 5 || len(parts[1]) != 20 || len(parts[2]) != 20 ||
		len(parts[3]) != 32 || len(parts[4]) != 64 {
		return identity.MembershipPublicationFence{}, fmt.Errorf("identity publication fence shape is invalid")
	}
	attempt, attemptErr := strconv.ParseUint(parts[1], 10, 64)
	revision, revisionErr := strconv.ParseUint(parts[2], 10, 64)
	if attemptErr != nil || revisionErr != nil || revision == 0 {
		return identity.MembershipPublicationFence{}, fmt.Errorf("identity publication fence counter is invalid")
	}
	if _, err := hex.DecodeString(parts[3]); err != nil {
		return identity.MembershipPublicationFence{}, fmt.Errorf("identity publication watermark digest is invalid")
	}
	if _, err := hex.DecodeString(parts[4]); err != nil {
		return identity.MembershipPublicationFence{}, fmt.Errorf("identity publication projection digest is invalid")
	}
	state := identity.MembershipPublicationFenceActive
	if parts[0] == "p" {
		state = identity.MembershipPublicationFencePublished
	} else if parts[0] != "a" {
		return identity.MembershipPublicationFence{}, fmt.Errorf("identity publication fence state is invalid")
	}
	fence := identity.MembershipPublicationFence{
		State: state, IdentityWatermark: fmt.Sprintf("identity_%020d_%s", revision, parts[3]),
		ProjectionDigest: "sha256:" + parts[4], Attempt: attempt,
	}
	if fence.Validate() != nil || identityFenceTuple(fence).User != user {
		return identity.MembershipPublicationFence{}, fmt.Errorf("identity publication fence is invalid")
	}
	return fence, nil
}

func identityFenceWatermarkParts(watermark string) (uint64, error) {
	parts := strings.Split(watermark, "_")
	if len(parts) != 3 || parts[0] != "identity" || len(parts[1]) != 20 || len(parts[2]) != 32 {
		return 0, fmt.Errorf("identity publication watermark is invalid")
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return 0, fmt.Errorf("identity publication watermark is invalid")
	}
	revision, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || revision == 0 {
		return 0, fmt.Errorf("identity publication watermark is invalid")
	}
	return revision, nil
}
