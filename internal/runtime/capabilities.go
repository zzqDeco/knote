package runtime

import (
	"strings"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
)

type sessionCapabilityMode uint8

const sessionCapabilityPermissioned sessionCapabilityMode = 1

// SessionCapabilityProfile is an immutable, per-session capability boundary.
// Its zero value is the backward-compatible default profile.
type SessionCapabilityProfile struct {
	mode sessionCapabilityMode
}

func DefaultSessionCapabilityProfile() SessionCapabilityProfile {
	return SessionCapabilityProfile{}
}

func PermissionedSessionCapabilityProfile() SessionCapabilityProfile {
	return SessionCapabilityProfile{mode: sessionCapabilityPermissioned}
}

func (p SessionCapabilityProfile) IsPermissioned() bool {
	return p.mode == sessionCapabilityPermissioned
}

func (p SessionCapabilityProfile) AllowsSlashCommand(command string) bool {
	if !p.IsPermissioned() {
		return true
	}
	command = strings.TrimSpace(command)
	if fields := strings.Fields(command); len(fields) > 0 {
		command = fields[0]
	}
	command = strings.TrimPrefix(command, "/")
	switch command {
	case "build", "commit", "release", "checkout",
		"tasks", "governance", "clear", "new", "resume", "help", "exit":
		return true
	default:
		return false
	}
}

func (p SessionCapabilityProfile) AllowsEinoTool(toolName string) bool {
	if !p.IsPermissioned() {
		return true
	}
	switch strings.TrimSpace(toolName) {
	case einotools.NameQuery, einotools.NameExplain:
		return true
	default:
		return false
	}
}
