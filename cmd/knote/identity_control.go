package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/zzqDeco/knote/internal/identity"
	"github.com/zzqDeco/knote/internal/protocol"
)

const (
	identityControlCommand        = "identity-control"
	identityControlDigestPrefix   = "sha256:"
	maxIdentityControlRequestSize = 256 << 10
)

var errIdentityControlRejected = errors.New("identity control request rejected")

type identityControlRequest struct {
	Version   string               `json:"version"`
	Operation string               `json:"operation"`
	Scope     protocol.TenantScope `json:"scope"`
	Input     json.RawMessage      `json:"input"`
}

type identityControlReceipt struct {
	Version           string `json:"version"`
	RequestDigest     string `json:"request_digest"`
	Changed           bool   `json:"changed"`
	RevisionNumber    uint64 `json:"revision_number"`
	IdentityWatermark string `json:"identity_watermark"`
}

type identityControlEmptyInput struct{}

type identityControlProviderInput struct {
	ProviderID string   `json:"provider_id"`
	Issuer     string   `json:"issuer"`
	Audiences  []string `json:"audiences"`
}

type identityControlUserUpsertInput struct {
	ProviderID        string `json:"provider_id"`
	ExternalID        string `json:"external_id"`
	ExternalSubjectID string `json:"external_subject_id"`
	PrincipalID       string `json:"principal_id"`
}

type identityControlResourceInput struct {
	ProviderID string `json:"provider_id"`
	ExternalID string `json:"external_id"`
}

type identityControlGroupUpsertInput struct {
	ProviderID  string `json:"provider_id"`
	ExternalID  string `json:"external_id"`
	GroupID     string `json:"group_id"`
	DisplayName string `json:"display_name"`
}

type identityControlMembershipUpsertInput struct {
	ProviderID      string `json:"provider_id"`
	GroupExternalID string `json:"group_external_id"`
	UserExternalID  string `json:"user_external_id"`
	Active          *bool  `json:"active"`
}

type identityControlMembershipReplaceInput struct {
	ProviderID      string    `json:"provider_id"`
	GroupExternalID string    `json:"group_external_id"`
	UserExternalIDs *[]string `json:"user_external_ids"`
}

type identityControlAction func(context.Context, *identity.LocalStore, protocol.TenantScope) (identity.Change, error)

func runIdentityControl(ctx context.Context, args []string, stdout io.Writer) error {
	if ctx == nil || stdout == nil {
		return errIdentityControlRejected
	}
	requestFD, confirmation, err := parseIdentityControlArgs(args)
	if err != nil {
		return errIdentityControlRejected
	}
	raw, err := readIdentityControlRequest(requestFD)
	if err != nil {
		return errIdentityControlRejected
	}
	defer clear(raw)
	digest := identityControlDigest(raw)
	if confirmation != digest {
		return errIdentityControlRejected
	}

	var request identityControlRequest
	if err := decodeStrictIdentityControlJSON(raw, &request); err != nil ||
		request.Version != protocol.EnterpriseContractVersion || request.Scope.Validate() != nil {
		return errIdentityControlRejected
	}
	action, err := prepareIdentityControlAction(request)
	if err != nil {
		return errIdentityControlRejected
	}
	if err := ctx.Err(); err != nil {
		return errIdentityControlRejected
	}
	root, err := requiredPermissionedEnv(identityStorePathEnv)
	if err != nil {
		return errIdentityControlRejected
	}
	store, err := identity.OpenLocalStore(root)
	if err != nil {
		return errIdentityControlRejected
	}
	change, err := action(ctx, store, request.Scope)
	if err != nil {
		return errIdentityControlRejected
	}
	receipt := identityControlReceipt{
		Version: protocol.EnterpriseContractVersion, RequestDigest: digest,
		Changed: change.Changed, RevisionNumber: change.Revision.Number,
		IdentityWatermark: change.Revision.Watermark,
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return errIdentityControlRejected
	}
	encoded = append(encoded, '\n')
	if written, err := stdout.Write(encoded); err != nil || written != len(encoded) {
		return errIdentityControlRejected
	}
	return nil
}

func parseIdentityControlArgs(args []string) (int, string, error) {
	if len(args) != 2 {
		return 0, "", errIdentityControlRejected
	}
	requestFD := -1
	confirmation := ""
	for _, argument := range args {
		switch {
		case strings.HasPrefix(argument, "--request-fd="):
			if requestFD != -1 {
				return 0, "", errIdentityControlRejected
			}
			value := strings.TrimPrefix(argument, "--request-fd=")
			parsed, err := strconv.ParseUint(value, 10, 31)
			if err != nil || parsed < 3 || strconv.FormatUint(parsed, 10) != value {
				return 0, "", errIdentityControlRejected
			}
			requestFD = int(parsed)
		case strings.HasPrefix(argument, "--confirm="):
			if confirmation != "" {
				return 0, "", errIdentityControlRejected
			}
			confirmation = strings.TrimPrefix(argument, "--confirm=")
			if !isCanonicalIdentityControlDigest(confirmation) {
				return 0, "", errIdentityControlRejected
			}
		default:
			return 0, "", errIdentityControlRejected
		}
	}
	if requestFD < 3 || confirmation == "" {
		return 0, "", errIdentityControlRejected
	}
	return requestFD, confirmation, nil
}

func readIdentityControlRequest(fd int) ([]byte, error) {
	file := os.NewFile(uintptr(fd), "knote-identity-control-request")
	if file == nil {
		return nil, errIdentityControlRejected
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxIdentityControlRequestSize+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) > maxIdentityControlRequestSize {
		clear(raw)
		return nil, errIdentityControlRejected
	}
	return raw, nil
}

func identityControlDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return identityControlDigestPrefix + hex.EncodeToString(sum[:])
}

func isCanonicalIdentityControlDigest(value string) bool {
	if len(value) != len(identityControlDigestPrefix)+sha256.Size*2 ||
		!strings.HasPrefix(value, identityControlDigestPrefix) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, identityControlDigestPrefix))
	return err == nil && len(decoded) == sha256.Size &&
		value == identityControlDigestPrefix+hex.EncodeToString(decoded)
}

func decodeStrictIdentityControlJSON(raw []byte, destination any) error {
	if len(bytes.TrimSpace(raw)) == 0 || destination == nil {
		return errIdentityControlRejected
	}
	if err := rejectDuplicateIdentityControlFields(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errIdentityControlRejected
	}
	return nil
}

func rejectDuplicateIdentityControlFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeIdentityControlJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errIdentityControlRejected
	}
	return nil
}

func consumeIdentityControlJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errIdentityControlRejected
			}
			if _, duplicate := seen[name]; duplicate {
				return errIdentityControlRejected
			}
			seen[name] = struct{}{}
			if err := consumeIdentityControlJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errIdentityControlRejected
		}
	case '[':
		for decoder.More() {
			if err := consumeIdentityControlJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errIdentityControlRejected
		}
	default:
		return errIdentityControlRejected
	}
	return nil
}

func prepareIdentityControlAction(request identityControlRequest) (identityControlAction, error) {
	if !isIdentityControlInputObject(request.Input) {
		return nil, errIdentityControlRejected
	}
	switch request.Operation {
	case "tenant.register":
		var input identityControlEmptyInput
		if err := decodeStrictIdentityControlJSON(request.Input, &input); err != nil {
			return nil, err
		}
		return func(ctx context.Context, store *identity.LocalStore, scope protocol.TenantScope) (identity.Change, error) {
			return store.RegisterTenant(ctx, scope)
		}, nil
	case "provider.register":
		var input identityControlProviderInput
		if err := decodeStrictIdentityControlJSON(request.Input, &input); err != nil {
			return nil, err
		}
		spec := identity.ProviderSpec{
			ProviderID: input.ProviderID, Issuer: input.Issuer, Audiences: input.Audiences,
		}
		if err := spec.Validate(); err != nil {
			return nil, err
		}
		return func(ctx context.Context, store *identity.LocalStore, scope protocol.TenantScope) (identity.Change, error) {
			_, change, err := store.UpsertProvider(ctx, scope, spec)
			return change, err
		}, nil
	case "user.upsert":
		var input identityControlUserUpsertInput
		if err := decodeStrictIdentityControlJSON(request.Input, &input); err != nil {
			return nil, err
		}
		upsert := identity.UserUpsert{
			ProviderID: input.ProviderID, ExternalID: input.ExternalID,
			ExternalSubjectID: input.ExternalSubjectID, PrincipalID: input.PrincipalID, Active: true,
		}
		if err := upsert.Validate(); err != nil {
			return nil, err
		}
		return func(ctx context.Context, store *identity.LocalStore, scope protocol.TenantScope) (identity.Change, error) {
			_, change, err := store.UpsertUser(ctx, scope, upsert)
			return change, err
		}, nil
	case "user.deprovision":
		var input identityControlResourceInput
		if err := decodeStrictIdentityControlJSON(request.Input, &input); err != nil {
			return nil, err
		}
		resource := identity.ExternalResourceRef{ProviderID: input.ProviderID, ExternalID: input.ExternalID}
		if err := resource.Validate(); err != nil {
			return nil, err
		}
		return func(ctx context.Context, store *identity.LocalStore, scope protocol.TenantScope) (identity.Change, error) {
			_, change, err := store.DeprovisionUser(ctx, scope, resource.ProviderID, resource.ExternalID)
			return change, err
		}, nil
	case "group.upsert":
		var input identityControlGroupUpsertInput
		if err := decodeStrictIdentityControlJSON(request.Input, &input); err != nil {
			return nil, err
		}
		upsert := identity.GroupUpsert{
			ProviderID: input.ProviderID, ExternalID: input.ExternalID,
			GroupID: input.GroupID, DisplayName: input.DisplayName, Active: true,
		}
		if err := upsert.Validate(); err != nil {
			return nil, err
		}
		return func(ctx context.Context, store *identity.LocalStore, scope protocol.TenantScope) (identity.Change, error) {
			_, change, err := store.UpsertGroup(ctx, scope, upsert)
			return change, err
		}, nil
	case "group.deprovision":
		var input identityControlResourceInput
		if err := decodeStrictIdentityControlJSON(request.Input, &input); err != nil {
			return nil, err
		}
		resource := identity.ExternalResourceRef{ProviderID: input.ProviderID, ExternalID: input.ExternalID}
		if err := resource.Validate(); err != nil {
			return nil, err
		}
		return func(ctx context.Context, store *identity.LocalStore, scope protocol.TenantScope) (identity.Change, error) {
			_, change, err := store.DeprovisionGroup(ctx, scope, resource.ProviderID, resource.ExternalID)
			return change, err
		}, nil
	case "membership.upsert":
		var input identityControlMembershipUpsertInput
		if err := decodeStrictIdentityControlJSON(request.Input, &input); err != nil || input.Active == nil {
			return nil, errIdentityControlRejected
		}
		upsert := identity.MembershipUpsert{
			ProviderID: input.ProviderID, GroupExternalID: input.GroupExternalID,
			UserExternalID: input.UserExternalID, Active: *input.Active,
		}
		if err := upsert.Validate(); err != nil {
			return nil, err
		}
		return func(ctx context.Context, store *identity.LocalStore, scope protocol.TenantScope) (identity.Change, error) {
			_, change, err := store.UpsertMembership(ctx, scope, upsert)
			return change, err
		}, nil
	case "membership.replace":
		var input identityControlMembershipReplaceInput
		if err := decodeStrictIdentityControlJSON(request.Input, &input); err != nil || input.UserExternalIDs == nil {
			return nil, errIdentityControlRejected
		}
		replacement := identity.MembershipReplace{
			ProviderID: input.ProviderID, GroupExternalID: input.GroupExternalID,
			UserExternalIDs: *input.UserExternalIDs,
		}
		if err := replacement.Validate(); err != nil {
			return nil, err
		}
		return func(ctx context.Context, store *identity.LocalStore, scope protocol.TenantScope) (identity.Change, error) {
			_, change, err := store.ReplaceGroupMembers(ctx, scope, replacement)
			return change, err
		}, nil
	default:
		return nil, errIdentityControlRejected
	}
}

func isIdentityControlInputObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}
