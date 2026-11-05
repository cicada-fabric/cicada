package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
)

const groupLocksCLIUsage = "usage: cicada group-locks read|acquire|renew|release --thread ID [--group-id ID] [--user-root ABS] [--hub ALIAS | --hub-id ID] [--node-id ID]; mutations require --slot N --expected-version N --idempotency-key KEY; renew/release require --generation N; acquire/renew accept --ttl-seconds 1..3600; acquire accepts --note TEXT; --recover reuses the exact saved original"

type groupLocksCLIOptions struct {
	Thread, GroupID, UserRoot, HubAlias, HubID, NodeID string
	Operation                                          string
	Intent                                             mcpGroupLockIntent
	Key                                                string
	Recover                                            bool
	Arguments                                          map[string]any
}

func groupLocksCommand(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(groupLocksCLIUsage)
	}
	return groupLocksOperatorCommand(args[0], args[1:], out)
}

func parseGroupLocksCLIArguments(action string, args []string) (groupLocksCLIOptions, error) {
	var result groupLocksCLIOptions
	tool := map[string]string{"read": "cicada_group_locks", "acquire": "cicada_group_lock_acquire", "renew": "cicada_group_lock_renew", "release": "cicada_group_lock_release"}[action]
	if tool == "" {
		return result, errors.New(groupLocksCLIUsage)
	}
	flags := flag.NewFlagSet("group-locks "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&result.Thread, "thread", "", "exact original owned Codex Thread selector")
	flags.StringVar(&result.GroupID, "group-id", "", "exact Group or authenticated cached selection")
	flags.StringVar(&result.UserRoot, "user-root", "", "selected Cicada user root")
	flags.StringVar(&result.HubAlias, "hub", "", "exact enabled Hub alias")
	flags.StringVar(&result.HubID, "hub-id", "", "exact Hub selection")
	flags.StringVar(&result.NodeID, "node-id", "", "exact Node selection")
	slot := flags.String("slot", "", "observed slot number")
	version := flags.String("expected-version", "", "observed slot version")
	generation := flags.String("generation", "", "observed held generation")
	ttl := flags.String("ttl-seconds", "", "explicit lifetime, 1..3600 seconds")
	note := flags.String("note", "", "optional Group purpose")
	key := flags.String("idempotency-key", "", "stable business key")
	recover := flags.Bool("recover", false, "recover the saved original")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || !localContextText(result.Thread, 128) {
		return result, errors.New(groupLocksCLIUsage)
	}
	selected := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { selected[f.Name] = true })
	if selected["hub"] && (selected["hub-id"] || !localNodeHubText(result.HubAlias, 128)) || selected["group-id"] && !localContextText(result.GroupID, 256) {
		return result, errors.New(groupLocksCLIUsage)
	}
	business := map[string]any{}
	for name, value := range map[string]string{"slot": *slot, "expected_version": *version, "generation": *generation, "ttl_seconds": *ttl} {
		flagName := map[string]string{"slot": "slot", "expected_version": "expected-version", "generation": "generation", "ttl_seconds": "ttl-seconds"}[name]
		if selected[flagName] {
			business[name] = json.Number(value)
		}
	}
	if selected["note"] {
		business["note"] = *note
	}
	if selected["idempotency-key"] {
		business["idempotency_key"] = *key
	}
	if selected["recover"] {
		business["recover"] = *recover
	}
	intent, stableKey, recovering, err := parseGroupLockMCPArguments(tool, business)
	if err != nil {
		return result, err
	}
	result.Operation, result.Intent, result.Key, result.Recover = groupLockOperation(tool), intent, stableKey, recovering
	result.Arguments = business
	return result, nil
}
