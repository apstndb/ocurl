package main

import (
	"bytes"
	"encoding/json"
	"golang.org/x/oauth2"
	"os/exec"
	"time"
)

type gcloudTokenSource struct {
	account string
}

type gcloudCredential struct {
	AccessToken string    `json:"access_token"`
	IdToken     string    `json:"id_token"`
	TokenExpiry time.Time `json:"token_expiry"`
}

func getGcloudCredential(account string) (*gcloudCredential, error) {
	var buf bytes.Buffer
	args := []string{"config", "config-helper", "--format=json", "--force-auth-refresh"}
	if account != "" {
		args = append(args, "--account="+account)
	}

	cmd := exec.Command("gcloud", args...)
	cmd.Stdout = &buf
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	parsed := struct {
		Credential gcloudCredential `json:"credential"`
	}{}
	err = json.Unmarshal(buf.Bytes(), &parsed)
	if err != nil {
		return nil, err
	}
	return &parsed.Credential, nil
}

func (gts *gcloudTokenSource) Token() (*oauth2.Token, error) {
	parsed, err := getGcloudCredential(gts.account)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: parsed.AccessToken,
		Expiry:      parsed.TokenExpiry,
	}, nil
}

func NewGcloudTokenSource(account string) (oauth2.TokenSource, error) {
	return &gcloudTokenSource{account}, nil
}

func GcloudIdToken(account string) (string, error) {
	credential, err := getGcloudCredential(account)
	if err != nil {
		return "", err
	}
	return credential.IdToken, nil
}
