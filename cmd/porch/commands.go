// Adapted from HallPass cmd/hallpass/commands.go (Apache-2.0).

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/aurimasniekis/go-porch/internal/buildinfo"
)

var errHelp = errors.New("help requested")

// command is a CLI subcommand. Nested commands use sub.
type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
	sub     []*command
}

func rootCommands() []*command {
	return []*command{
		{name: "version", summary: "print version information", run: runVersion},
		{name: "serve", summary: "run the Porch server", run: runServe},
		{name: "migrate", summary: "apply pending database migrations (takes the data-directory lock)", run: runMigrate},
		{name: "openapi", summary: "print the management API OpenAPI 3.1 document", run: runOpenAPI},
		{name: "healthcheck", summary: "probe the management listener's /readyz (for container health checks)", run: runHealthcheck},
		{name: "config", summary: "configuration tools", sub: []*command{
			{name: "check", summary: "validate the configuration and print the effective settings", run: runConfigCheck},
		}},
		{name: "keys", summary: "key management", sub: []*command{
			{name: "init", summary: "generate a new KEK file (mode 0400)", run: runKeysInit},
			{name: "status", summary: "show keyring purposes and versions", run: runKeysStatus},
			{name: "rotate", summary: "rotate a purpose key (old version stays decrypt-only)", run: runKeysRotate},
			{name: "retire", summary: "retire a decrypt-only purpose key version once nothing uses it", run: runKeysRetire},
		}},
		{name: "admin", summary: "host-side administration (needs the data-directory lock and the KEK)", sub: []*command{
			{name: "setup-token", summary: "issue a single-use setup token for the first owner", run: runSetupToken},
		}},
		{name: "audit", summary: "audit log tools", sub: []*command{
			{name: "verify", summary: "verify the audit hash chain", run: runAuditVerify},
		}},
	}
}

func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return dispatchIn(ctx, "porch", rootCommands(), args, stdout, stderr)
}

func dispatchIn(ctx context.Context, path string, cmds []*command, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		printUsage(stdout, path, cmds)
		if len(args) == 0 {
			return &exitError{code: 2, err: errors.New("missing command")}
		}
		return errHelp
	}
	for _, c := range cmds {
		if c.name != args[0] {
			continue
		}
		if c.sub != nil {
			return dispatchIn(ctx, path+" "+c.name, c.sub, args[1:], stdout, stderr)
		}
		return c.run(ctx, args[1:], stdout, stderr)
	}
	printUsage(stderr, path, cmds)
	return &exitError{code: 2, err: fmt.Errorf("unknown command %q", args[0])}
}

func printUsage(w io.Writer, path string, cmds []*command) {
	fmt.Fprintf(w, "Usage: %s <command> [flags]\n\nCommands:\n", path)
	sorted := append([]*command(nil), cmds...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	for _, c := range sorted {
		fmt.Fprintf(w, "  %-14s %s\n", c.name, c.summary)
	}
}

// newFlagSet returns a flag set that reports errors instead of exiting.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelp
		}
		return &exitError{code: 2, err: err}
	}
	if fs.NArg() > 0 {
		return &exitError{code: 2, err: fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))}
	}
	return nil
}

func runVersion(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("version", stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	info := buildinfo.Get()
	if *asJSON {
		enc := json.NewEncoder(stdout)
		return enc.Encode(info)
	}
	_, err := fmt.Fprintln(stdout, info.String())
	return err
}
