package main

import (
	"bytes"
	"context"
	"encoding/json"
	"golang.org/x/oauth2"
	"os/exec"
	"time"
)

type gcloudTokenSource struct {
	cfg *gcloudConfig
}

type gcloudCredential struct {
	AccessToken string    `json:"access_token"`
	IdToken     string    `json:"id_token"`
	TokenExpiry time.Time `json:"token_expiry"`
}

type gcloudConfig struct {
	Credential gcloudCredential `json:"credential"`
	Core       struct {
		Account string `json:"account"`
	} `json:"core"`
}

func getGcloudConfig(account string) (*gcloudConfig, error) {
	var buf bytes.Buffer
	args := []string{"config", "config-helper", "--format=json"}
	if account != "" {
		args = append(args, "--account="+account)
	}

	cmd := exec.Command("gcloud", args...)
	cmd.Stdout = &buf
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	var parsed gcloudConfig
	err = json.Unmarshal(buf.Bytes(), &parsed)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func getGcloudCredential(account string) (*gcloudCredential, error) {
	config, err := getGcloudConfig(account)
	if err != nil {
		return nil, err
	}
	return &config.Credential, nil
}

func (gts *gcloudTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: gts.cfg.Credential.AccessToken,
		Expiry:      gts.cfg.Credential.TokenExpiry,
	}, nil
}

func newGcloudTokenSource(account string) (oauth2.TokenSource, error) {
	cfg, err := getGcloudConfig(account)
	if err != nil {
		return nil, err
	}

	return &gcloudTokenSource{cfg}, nil
}

func gcloudIdToken(account string) (string, error) {
	credential, err := getGcloudCredential(account)
	if err != nil {
		return "", err
	}
	return credential.IdToken, nil
}

func (gts *gcloudTokenSource) Email() (string, error) {
	return gts.cfg.Core.Account, nil
}

func (gts *gcloudTokenSource) AccessTokenWithoutScopes(ctx context.Context) (string, error) {
	return gts.cfg.Credential.AccessToken, nil
}

func (gts *gcloudTokenSource) IDTokenWithoutAudience(ctx context.Context) (string, error) {
	return gts.cfg.Credential.IdToken, nil
}
