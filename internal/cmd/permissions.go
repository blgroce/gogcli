package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"
)

// PermissionsFile defines the JSON schema for GOG_PERMISSIONS_FILE.
//
//	{
//	  "default_account": "agent@example.com",
//	  "accounts": {
//	    "agent@example.com":  { "gmail": "rw", "calendar": "rw" },
//	    "owner@example.com":  { "gmail": "r",  "calendar": "r"  }
//	  }
//	}
//
// Permission values: "rw" (read+write), "r" (read-only), "" (no access).
// Unlisted services default to no access.
type PermissionsFile struct {
	DefaultAccount string                       `json:"default_account"`
	Accounts       map[string]map[string]string `json:"accounts"`
}

// enforcePermissions checks the resolved command against per-account, per-service
// permissions loaded from GOG_PERMISSIONS_FILE. It blocks write operations on
// read-only services and any operations on no-access services.
//
// Returns nil if no permissions file is configured (opt-in feature).
func enforcePermissions(kctx *kong.Context, accountFlag string) error {
	path := strings.TrimSpace(os.Getenv("GOG_PERMISSIONS_FILE"))
	if path == "" {
		return nil // no permissions file → unrestricted
	}

	perms, err := loadPermissions(path)
	if err != nil {
		return fmt.Errorf("permissions: %w", err)
	}

	// Parse command path: e.g. "gmail send", "calendar create", "drive ls"
	cmdParts := strings.Fields(kctx.Command())
	if len(cmdParts) == 0 {
		return nil
	}
	service := normalizeService(cmdParts[0])

	// Always-allowed commands (no Google API calls)
	if isAlwaysAllowed(service) {
		return nil
	}

	// Resolve the account email
	account := resolveAccountForPermissions(accountFlag, perms.DefaultAccount)
	if account == "" {
		// No account resolved — let the command itself handle the error
		return nil
	}

	// Look up account permissions
	acctPerms, ok := perms.Accounts[account]
	if !ok {
		return &ExitError{
			Code: exitCodePermissionDenied,
			Err:  fmt.Errorf("account %q is not configured in permissions", account),
		}
	}

	// Look up service permission level
	level := strings.TrimSpace(strings.ToLower(acctPerms[service]))

	// No access
	if level == "" {
		return &ExitError{
			Code: exitCodePermissionDenied,
			Err:  fmt.Errorf("%s access is not permitted for %s", service, account),
		}
	}

	// Full access
	if level == "rw" {
		return nil
	}

	// Read-only: classify the operation
	if level == "r" {
		if isWriteCommand(cmdParts) {
			return &ExitError{
				Code: exitCodePermissionDenied,
				Err:  fmt.Errorf("%s write access is not granted for %s (read-only)", service, account),
			}
		}
		return nil // read operation on read-only → allowed
	}

	// Unknown permission level → deny (fail-closed)
	return &ExitError{
		Code: exitCodePermissionDenied,
		Err:  fmt.Errorf("unknown permission level %q for %s/%s", level, account, service),
	}
}

func loadPermissions(path string) (*PermissionsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var pf PermissionsFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &pf, nil
}

// resolveAccountForPermissions resolves the account email from the --account flag,
// GOG_ACCOUNT env var, or the permissions file default. This is a lightweight
// resolution that does NOT touch the keyring (unlike requireAccount).
func resolveAccountForPermissions(flag, defaultAccount string) string {
	if v := strings.TrimSpace(flag); v != "" && v != "auto" && v != "default" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("GOG_ACCOUNT")); v != "" && v != "auto" && v != "default" {
		return v
	}
	return strings.TrimSpace(defaultAccount)
}

// normalizeService maps command aliases to canonical service names.
func normalizeService(cmd string) string {
	switch strings.ToLower(cmd) {
	case "mail", "email":
		return "gmail"
	case "cal":
		return "calendar"
	case "drv":
		return "drive"
	case "doc":
		return "docs"
	case "slide":
		return "slides"
	case "sheet":
		return "sheets"
	case "contact":
		return "contacts"
	case "task":
		return "tasks"
	case "person":
		return "people"
	case "group":
		return "groups"
	case "class":
		return "classroom"
	case "form":
		return "forms"
	case "script", "apps-script":
		return "appscript"
	// Desire-path aliases (top-level shortcuts)
	case "send":
		return "gmail"
	case "ls", "list":
		return "drive"
	case "search", "find":
		return "drive"
	case "download", "dl":
		return "drive"
	case "upload", "up", "put":
		return "drive"
	default:
		return strings.ToLower(cmd)
	}
}

func isAlwaysAllowed(service string) bool {
	switch service {
	case "auth", "config", "version", "time", "completion",
		"__complete", "exit-codes", "exitcodes", "agent", "schema",
		"login", "logout", "status", "open", "me", "whoami":
		return true
	default:
		return false
	}
}

// isWriteCommand classifies a parsed command path as a write operation.
// Uses fail-closed logic: unknown subcommands are treated as writes.
func isWriteCommand(cmdParts []string) bool {
	if len(cmdParts) == 0 {
		return false
	}

	// Build lookup key from command parts (service:sub1 or service:sub1:sub2)
	service := normalizeService(cmdParts[0])

	// Desire-path shortcuts that are writes
	switch service + ":" + cmdParts[0] {
	case "gmail:send", "drive:upload", "drive:up", "drive:put":
		return true
	}
	// Desire-path shortcuts that are reads
	switch cmdParts[0] {
	case "ls", "list", "search", "find", "download", "dl", "me", "whoami", "status":
		return false
	}

	// For regular commands: service + subcommand(s)
	if len(cmdParts) < 2 {
		return false // bare service name = help display
	}
	sub1 := strings.ToLower(cmdParts[1])
	sub2 := ""
	if len(cmdParts) >= 3 {
		sub2 = strings.ToLower(cmdParts[2])
	}

	key2 := service + ":" + sub1
	key3 := ""
	if sub2 != "" {
		key3 = service + ":" + sub1 + ":" + sub2
	}

	// Check 3-level key first, then 2-level
	if key3 != "" {
		if _, ok := readCommands[key3]; ok {
			return false
		}
	}
	if _, ok := readCommands[key2]; ok {
		return false
	}

	// Fail-closed: unknown = write
	return true
}

// readCommands is the set of known read-only command paths.
// Anything not in this set is treated as a write (fail-closed).
var readCommands = map[string]struct{}{
	// Gmail
	"gmail:search":              {},
	"gmail:messages":            {}, // parent — subcommands are read
	"gmail:messages:search":     {},
	"gmail:messages:list":       {},
	"gmail:messages:get":        {},
	"gmail:get":                 {},
	"gmail:attachment":          {},
	"gmail:url":                 {},
	"gmail:history":             {},
	"gmail:thread:get":          {},
	"gmail:thread:attachments":  {},
	"gmail:labels:list":         {},
	"gmail:labels:get":          {},
	"gmail:track:opens":         {},
	"gmail:track:status":        {},
	"gmail:drafts:list":         {},
	"gmail:drafts:get":          {},
	"gmail:settings:filters":    {}, // list filters = read
	"gmail:settings:forwarding": {}, // list forwarding = read
	"gmail:settings:delegates":  {}, // list delegates = read
	"gmail:settings:sendas":     {}, // list send-as = read
	"gmail:settings:vacation":   {}, // get vacation = read

	// Calendar
	"calendar:calendars": {},
	"calendar:acl":       {},
	"calendar:events":    {},
	"calendar:event":     {},
	"calendar:freebusy":  {},
	"calendar:colors":    {},
	"calendar:conflicts": {},
	"calendar:search":    {},
	"calendar:time":      {},
	"calendar:users":     {},
	"calendar:team":      {},

	// Drive
	"drive:ls":              {},
	"drive:search":          {},
	"drive:get":             {},
	"drive:download":        {},
	"drive:permissions":     {},
	"drive:url":             {},
	"drive:comments:list":   {},
	"drive:comments:get":    {},
	"drive:drives":          {},
	"drive:drives:list":     {},
	"drive:drives:get":      {},
	"drive:drives:themes":   {},

	// Contacts
	"contacts:search":           {},
	"contacts:list":             {},
	"contacts:get":              {},
	"contacts:directory":        {},
	"contacts:directory:list":   {},
	"contacts:directory:search": {},
	"contacts:other":            {},
	"contacts:other:list":       {},
	"contacts:other:search":     {},

	// Sheets
	"sheets:get":      {},
	"sheets:metadata": {},
	"sheets:export":   {},

	// Docs
	"docs:export":        {},
	"docs:info":          {},
	"docs:cat":           {},
	"docs:comments":      {}, // parent
	"docs:comments:list": {},
	"docs:comments:get":  {},

	// Slides
	"slides:export": {},
	"slides:info":   {},

	// Tasks
	"tasks:lists":      {},
	"tasks:lists:list": {},
	"tasks:list":       {},
	"tasks:get":        {},

	// Chat
	"chat:spaces":        {},
	"chat:spaces:list":   {},
	"chat:spaces:find":   {},
	"chat:messages":      {},
	"chat:messages:list": {},
	"chat:threads":       {},
	"chat:threads:list":  {},

	// People (all read-only)
	"people:me":        {},
	"people:get":       {},
	"people:search":    {},
	"people:relations": {},

	// Groups (all read-only)
	"groups:list":    {},
	"groups:members": {},

	// Keep (all read-only)
	"keep:list":       {},
	"keep:get":        {},
	"keep:search":     {},
	"keep:attachment":  {},
	"keep:attachments": {},

	// Classroom (read operations)
	"classroom:courses":                  {},
	"classroom:courses:list":             {},
	"classroom:courses:get":              {},
	"classroom:courses:url":              {},
	"classroom:students":                 {},
	"classroom:students:list":            {},
	"classroom:teachers":                 {},
	"classroom:teachers:list":            {},
	"classroom:roster":                   {},
	"classroom:coursework":               {},
	"classroom:coursework:list":          {},
	"classroom:coursework:get":           {},
	"classroom:materials":                {},
	"classroom:materials:list":           {},
	"classroom:materials:get":            {},
	"classroom:submissions":              {},
	"classroom:submissions:list":         {},
	"classroom:submissions:get":          {},
	"classroom:announcements":            {},
	"classroom:announcements:list":       {},
	"classroom:announcements:get":        {},
	"classroom:topics":                   {},
	"classroom:topics:list":              {},
	"classroom:topics:get":               {},
	"classroom:invitations":              {},
	"classroom:invitations:list":         {},
	"classroom:invitations:get":          {},
	"classroom:guardians":                {},
	"classroom:guardians:list":           {},
	"classroom:guardians:get":            {},
	"classroom:guardian-invitations":      {},
	"classroom:guardian-invitations:list": {},
	"classroom:guardian-invitations:get":  {},
	"classroom:profile":                  {},

	// Forms (read operations)
	"forms:get":             {},
	"forms:responses":       {},
	"forms:responses:list":  {},
	"forms:responses:get":   {},

	// AppScript (read operations)
	"appscript:list":    {},
	"appscript:get":     {},
	"appscript:content": {},
	"appscript:metrics": {},
}
