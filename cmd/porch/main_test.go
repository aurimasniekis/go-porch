package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "porch ") {
		t.Fatalf("unexpected output %q", out.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"nope"}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}
