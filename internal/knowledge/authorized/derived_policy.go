package authorized

import (
	"fmt"
	"reflect"

	"github.com/zzqDeco/knote/internal/protocol"
)

func selectAuthorizedEvidenceItems(
	items []protocol.EvidenceItem,
	checks map[string]objectCheck,
) []protocol.EvidenceItem {
	selected := make([]protocol.EvidenceItem, 0, len(items))
	for _, item := range items {
		authorized, ok := selectAuthorizedEvidenceItem(item, checks)
		if ok {
			selected = append(selected, authorized)
		}
	}
	return selected
}

func selectAuthorizedEvidenceItem(
	item protocol.EvidenceItem,
	checks map[string]objectCheck,
) (protocol.EvidenceItem, bool) {
	return selectEvidenceItem(item, func(resource protocol.ResourceHandle) bool {
		return resourceAllowed(resource, checks)
	})
}

func selectEvidenceItem(
	item protocol.EvidenceItem,
	allowed func(protocol.ResourceHandle) bool,
) (protocol.EvidenceItem, bool) {
	if allowed == nil || !allowed(item.Resource) {
		return protocol.EvidenceItem{}, false
	}
	mode := item.Derivation
	if item.Resource.Type == protocol.ResourceDerivedArtifact && mode == "" {
		mode = protocol.DerivationAllRequired
	}
	if err := protocol.ValidateProvenance(mode, item.Supports); err != nil {
		return protocol.EvidenceItem{}, false
	}

	selected := cloneEvidenceItems([]protocol.EvidenceItem{item})[0]
	switch mode {
	case protocol.DerivationAnySupport:
		selected.Supports = selected.Supports[:0]
		for _, support := range item.Supports {
			if supportAllowedBy(support, allowed) {
				selected.Supports = append(selected.Supports, cloneProvenanceSupport(support))
			}
		}
		if len(selected.Supports) == 0 {
			return protocol.EvidenceItem{}, false
		}
	case protocol.DerivationAllRequired:
		for _, support := range item.Supports {
			if !supportAllowedBy(support, allowed) {
				return protocol.EvidenceItem{}, false
			}
		}
	default:
		return protocol.EvidenceItem{}, false
	}
	return selected, true
}

func supportAllowedBy(support protocol.ProvenanceSupport, allowed func(protocol.ResourceHandle) bool) bool {
	if allowed == nil || !allowed(support.Resource) {
		return false
	}
	for _, evidence := range support.Evidence {
		if !allowed(evidence) {
			return false
		}
	}
	return true
}

func resourceAllowed(resource protocol.ResourceHandle, checks map[string]objectCheck) bool {
	checked, ok := checks[resource.AuthorizationID]
	return ok && checked.allowed
}

func selectBoundEvidenceItems(
	items []protocol.EvidenceItem,
	bound map[protocol.ResourceID]protocol.ProtectedResourceBinding,
) ([]protocol.EvidenceItem, bool) {
	selected := make([]protocol.EvidenceItem, len(items))
	for index, item := range items {
		selectedItem, ok := selectEvidenceItem(item, func(resource protocol.ResourceHandle) bool {
			binding, exists := bound[resource.ResourceID]
			return exists && binding.Resource == resource
		})
		if !ok {
			return nil, false
		}
		selected[index] = selectedItem
	}
	return selected, true
}

func reloadSelectedEvidenceItems(
	loaded []protocol.EvidenceItem,
	selected []protocol.EvidenceItem,
) ([]protocol.EvidenceItem, bool) {
	if len(loaded) != len(selected) {
		return nil, false
	}
	result := make([]protocol.EvidenceItem, len(selected))
	for index := range selected {
		item, ok := reloadSelectedEvidenceItem(loaded[index], selected[index])
		if !ok {
			return nil, false
		}
		result[index] = item
	}
	return result, true
}

func reloadSelectedEvidenceItem(
	loaded protocol.EvidenceItem,
	selected protocol.EvidenceItem,
) (protocol.EvidenceItem, bool) {
	if loaded.Resource != selected.Resource || loaded.Content != selected.Content ||
		loaded.Derivation != selected.Derivation || loaded.Citation != selected.Citation {
		return protocol.EvidenceItem{}, false
	}
	mode := selected.Derivation
	if selected.Resource.Type == protocol.ResourceDerivedArtifact && mode == "" {
		mode = protocol.DerivationAllRequired
	}
	if err := protocol.ValidateProvenance(mode, loaded.Supports); err != nil {
		return protocol.EvidenceItem{}, false
	}
	if err := protocol.ValidateProvenance(mode, selected.Supports); err != nil {
		return protocol.EvidenceItem{}, false
	}

	switch mode {
	case protocol.DerivationAllRequired:
		if !reflect.DeepEqual(loaded.Supports, selected.Supports) {
			return protocol.EvidenceItem{}, false
		}
	case protocol.DerivationAnySupport:
		loadedByID := make(map[string]protocol.ProvenanceSupport, len(loaded.Supports))
		for _, support := range loaded.Supports {
			loadedByID[support.SupportID] = support
		}
		for _, support := range selected.Supports {
			current, ok := loadedByID[support.SupportID]
			if !ok || !reflect.DeepEqual(current, support) {
				return protocol.EvidenceItem{}, false
			}
		}
	default:
		return protocol.EvidenceItem{}, false
	}
	return cloneEvidenceItems([]protocol.EvidenceItem{selected})[0], true
}

func cloneProvenanceSupport(source protocol.ProvenanceSupport) protocol.ProvenanceSupport {
	clone := source
	if source.Evidence != nil {
		clone.Evidence = append([]protocol.ResourceHandle(nil), source.Evidence...)
	}
	return clone
}

func checkedEvidenceForItems(
	authorization protocol.AuthorizationContext,
	items []protocol.EvidenceItem,
	checks map[string]objectCheck,
) (checkedEvidence, error) {
	handles, boundaries, projection, err := collectEvidenceHandles(authorization, items)
	if err != nil {
		return checkedEvidence{}, err
	}
	objects := make(map[string]objectCheck, len(handles))
	for _, resource := range handles {
		checked, ok := checks[resource.AuthorizationID]
		if !ok || !checked.allowed {
			return checkedEvidence{}, fmt.Errorf("selected evidence resource %s is not authorized", resource.ResourceID)
		}
		objects[resource.AuthorizationID] = checked
	}
	return checkedEvidence{
		handles: handles, boundaries: boundaries, projection: projection, objects: objects,
	}, nil
}
