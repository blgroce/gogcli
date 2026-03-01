package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeService(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"gmail", "gmail"},
		{"mail", "gmail"},
		{"email", "gmail"},
		{"calendar", "calendar"},
		{"cal", "calendar"},
		{"drive", "drive"},
		{"drv", "drive"},
		{"send", "gmail"},
		{"upload", "drive"},
		{"ls", "drive"},
	}
	for _, tt := range tests {
		if got := normalizeService(tt.input); got != tt.want {
			t.Errorf("normalizeService(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsAlwaysAllowed(t *testing.T) {
	allowed := []string{"auth", "config", "version", "time", "completion", "agent", "schema"}
	for _, s := range allowed {
		if !isAlwaysAllowed(s) {
			t.Errorf("expected %q to be always allowed", s)
		}
	}
	notAllowed := []string{"gmail", "calendar", "drive", "contacts", "sheets"}
	for _, s := range notAllowed {
		if isAlwaysAllowed(s) {
			t.Errorf("expected %q to NOT be always allowed", s)
		}
	}
}

func TestIsWriteCommand(t *testing.T) {
	tests := []struct {
		cmd  []string
		want bool
	}{
		// Read commands
		{[]string{"gmail", "search", "test"}, false},
		{[]string{"gmail", "get", "123"}, false},
		{[]string{"gmail", "labels", "list"}, false},
		{[]string{"calendar", "events"}, false},
		{[]string{"calendar", "freebusy"}, false},
		{[]string{"drive", "ls"}, false},
		{[]string{"drive", "search", "query"}, false},
		{[]string{"drive", "download", "123"}, false},
		{[]string{"contacts", "search", "name"}, false},
		{[]string{"sheets", "get", "id", "A1:B2"}, false},
		{[]string{"docs", "cat", "id"}, false},
		{[]string{"people", "me"}, false},
		{[]string{"groups", "list"}, false},
		{[]string{"keep", "search", "q"}, false},

		// Write commands
		{[]string{"gmail", "send"}, true},
		{[]string{"calendar", "create"}, true},
		{[]string{"calendar", "update"}, true},
		{[]string{"calendar", "delete"}, true},
		{[]string{"drive", "upload", "file.txt"}, true},
		{[]string{"drive", "mkdir", "folder"}, true},
		{[]string{"drive", "delete", "id"}, true},
		{[]string{"drive", "share", "id"}, true},
		{[]string{"contacts", "create"}, true},
		{[]string{"contacts", "delete", "id"}, true},
		{[]string{"sheets", "update", "id", "A1"}, true},
		{[]string{"sheets", "create", "title"}, true},
		{[]string{"docs", "create", "title"}, true},
		{[]string{"tasks", "add", "listid"}, true},

		// Desire-path shortcuts
		{[]string{"send"}, true},
		{[]string{"upload", "file.txt"}, true},
		{[]string{"ls"}, false},
		{[]string{"search", "query"}, false},
		{[]string{"download", "id"}, false},

		// Bare service name = help (not a write)
		{[]string{"gmail"}, false},
		{[]string{"calendar"}, false},

		// Unknown subcommands = write (fail-closed)
		{[]string{"gmail", "newcmd"}, true},
		{[]string{"drive", "something"}, true},
	}

	for _, tt := range tests {
		got := isWriteCommand(tt.cmd)
		if got != tt.want {
			t.Errorf("isWriteCommand(%v) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}

func TestLoadPermissions(t *testing.T) {
	pf := PermissionsFile{
		DefaultAccount: "agent@example.com",
		Accounts: map[string]map[string]string{
			"agent@example.com": {"gmail": "rw", "calendar": "rw"},
			"owner@example.com": {"gmail": "r", "calendar": "r"},
		},
	}
	data, _ := json.Marshal(pf)
	tmpFile := filepath.Join(t.TempDir(), "perms.json")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadPermissions(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DefaultAccount != "agent@example.com" {
		t.Errorf("default_account = %q, want %q", loaded.DefaultAccount, "agent@example.com")
	}
	if loaded.Accounts["agent@example.com"]["gmail"] != "rw" {
		t.Errorf("agent gmail = %q, want %q", loaded.Accounts["agent@example.com"]["gmail"], "rw")
	}
	if loaded.Accounts["owner@example.com"]["gmail"] != "r" {
		t.Errorf("owner gmail = %q, want %q", loaded.Accounts["owner@example.com"]["gmail"], "r")
	}
}

func TestResolveAccountForPermissions(t *testing.T) {
	// Flag takes precedence
	got := resolveAccountForPermissions("flag@example.com", "default@example.com")
	if got != "flag@example.com" {
		t.Errorf("got %q, want flag@example.com", got)
	}

	// Default used when flag empty
	got = resolveAccountForPermissions("", "default@example.com")
	if got != "default@example.com" {
		t.Errorf("got %q, want default@example.com", got)
	}

	// "auto" and "default" are ignored
	got = resolveAccountForPermissions("auto", "default@example.com")
	if got != "default@example.com" {
		t.Errorf("got %q, want default@example.com", got)
	}
}
