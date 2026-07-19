package runtime

import (
	"testing"

	einotools "github.com/zzqDeco/knote/internal/eino/tools"
)

func TestSessionCapabilityProfiles(t *testing.T) {
	zero := SessionCapabilityProfile{}
	defaults := DefaultSessionCapabilityProfile()
	permissioned := PermissionedSessionCapabilityProfile()
	if zero != defaults || zero.IsPermissioned() || !permissioned.IsPermissioned() {
		t.Fatalf("profile identities zero=%+v default=%+v permissioned=%+v", zero, defaults, permissioned)
	}

	slashCommands := []struct {
		command             string
		permissionedAllowed bool
	}{
		{command: "/build", permissionedAllowed: true},
		{command: "commit", permissionedAllowed: true},
		{command: "release", permissionedAllowed: true},
		{command: "checkout", permissionedAllowed: true},
		{command: "tasks", permissionedAllowed: true},
		{command: "governance", permissionedAllowed: true},
		{command: "clear", permissionedAllowed: true},
		{command: "new", permissionedAllowed: true},
		{command: "resume", permissionedAllowed: true},
		{command: "help", permissionedAllowed: true},
		{command: "exit", permissionedAllowed: true},
		{command: "details"},
		{command: "versions"},
		{command: "status"},
		{command: "settings"},
		{command: "model"},
		{command: "diff"},
		{command: "eval"},
		{command: "unknown"},
		{command: ""},
	}
	for _, test := range slashCommands {
		if !zero.AllowsSlashCommand(test.command) || !defaults.AllowsSlashCommand(test.command) {
			t.Errorf("default profile rejected slash command %q", test.command)
		}
		if got := permissioned.AllowsSlashCommand(test.command); got != test.permissionedAllowed {
			t.Errorf("permissioned slash %q allowed=%t, want %t", test.command, got, test.permissionedAllowed)
		}
	}

	tools := []struct {
		name                string
		permissionedAllowed bool
	}{
		{name: einotools.NameQuery, permissionedAllowed: true},
		{name: einotools.NameExplain, permissionedAllowed: true},
		{name: einotools.NameBuild},
		{name: einotools.NameEval},
		{name: einotools.NameDiff},
		{name: einotools.NameVersions},
		{name: einotools.NameCommit},
		{name: einotools.NameRelease},
		{name: einotools.NameCheckout},
		{name: "unknown"},
	}
	for _, test := range tools {
		if !zero.AllowsEinoTool(test.name) || !defaults.AllowsEinoTool(test.name) {
			t.Errorf("default profile rejected Eino tool %q", test.name)
		}
		if got := permissioned.AllowsEinoTool(test.name); got != test.permissionedAllowed {
			t.Errorf("permissioned Eino tool %q allowed=%t, want %t", test.name, got, test.permissionedAllowed)
		}
	}
}
