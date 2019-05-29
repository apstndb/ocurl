package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"golang.org/x/oauth2/google"
)

// copy from golang.org/x/oauth2/google.FindDefaultCredentials
func wellKnownFileCredentials(ctx context.Context, scopes ...string) (*google.Credentials, error) {
	filename := wellKnownFile()
	if creds, err := readCredentialsFile(ctx, filename, scopes); err == nil {
		return creds, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("google: error getting credentials using well-known file (%v): %v", filename, err)
	}
	return nil, fmt.Errorf("google: could not find well-known file credentials")
}

func wellKnownFile() string {
	const f = "application_default_credentials.json"
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "gcloud", f)
	}
	return filepath.Join(guessUnixHomeDir(), ".config", "gcloud", f)
}

func guessUnixHomeDir() string {
	// Prefer $HOME over user.Current due to glibc bug: golang.org/issue/13470
	if v := os.Getenv("HOME"); v != "" {
		return v
	}
	// Else, fall back to user.Current:
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

func readCredentialsFile(ctx context.Context, filename string, scopes []string) (*google.Credentials, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return google.CredentialsFromJSON(ctx, b, scopes...)
}
