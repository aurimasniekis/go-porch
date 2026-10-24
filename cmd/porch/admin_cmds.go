package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/app"
	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
)

// resolveUser accepts a user ID or a primary email.
func resolveUser(ctx context.Context, a *app.App, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ids.Valid(ids.User, ref) {
		return ref, nil
	}
	us, err := a.Store.R().GetUsersByPrimaryEmail(ctx, domain.NullStr(strings.ToLower(ref)))
	if err != nil {
		return "", err
	}
	switch len(us) {
	case 0:
		return "", fmt.Errorf("no user with email %q", ref)
	case 1:
		return us[0].ID, nil
	}
	return "", fmt.Errorf("several users have email %q; pass the user ID", ref)
}

func runRecover(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("admin recover", stderr)
	cfgPath := configFlag(fs)
	user := fs.String("user", "", "user ID or primary email")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *user == "" {
		return &exitError{code: 2, err: errors.New("--user is required")}
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	uid, err := resolveUser(ctx, a, *user)
	if err != nil {
		return err
	}
	tok, exp, err := a.Local.IssueRecoveryLink(ctx, uid)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "One-time recovery link for %s (expires %s):\n\n  %s/recovery?token=%s\n\nUsing it is audited and raises a "+
		"critical alert until an operator acknowledges it.\n", uid, exp.UTC().Format(time.RFC3339), a.Cfg.PublicOrigin(), tok)
	return err
}

func runUnlockBackup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("admin unlock-backup", stderr)
	cfgPath := configFlag(fs)
	user := fs.String("user", "", "user ID or primary email")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *user == "" {
		return &exitError{code: 2, err: errors.New("--user is required")}
	}
	a, err := openApp(ctx, *cfgPath, stderr)
	if err != nil {
		return err
	}
	defer a.Close()
	uid, err := resolveUser(ctx, a, *user)
	if err != nil {
		return err
	}
	if err := a.Local.Unlock(ctx, audit.CLI, uid); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "backup login unlocked for %s\n", uid)
	return err
}
