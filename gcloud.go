package main

import (
	"context"
	"time"

	"golang.org/x/oauth2"
)

type gcloudTokenSource struct {
	cfg *gcloudConfig
}

type gcloudConfig struct {
	Credential struct {
		AccessToken string    `json:"access_token"`
		IdToken     string    `json:"id_token"`
		TokenExpiry time.Time `json:"token_expiry"`
	} `json:"credential"`
	Configuration struct {
		Properties struct {
			Core struct {
				Account string `json:"account"`
			} `json:"core"`
		} `json:"properties"`
	} `json:"configuration"`
}

func GcloudTokenSource(account string) (oauth2.TokenSource, error) {
	cfg, err := fetchGcloudConfig(account)
	if err != nil {
		return nil, err
	}

	return &gcloudTokenSource{cfg}, nil
}

func (gts *gcloudTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: gts.cfg.Credential.AccessToken,
		Expiry:      gts.cfg.Credential.TokenExpiry,
	}, nil
}

func (gts *gcloudTokenSource) Email() (string, error) {
	return gts.cfg.Configuration.Properties.Core.Account, nil
}

func (gts *gcloudTokenSource) AccessTokenWithoutScopes(ctx context.Context) (string, error) {
	return gts.cfg.Credential.AccessToken, nil
}

func (gts *gcloudTokenSource) IDTokenWithoutAudience(ctx context.Context) (string, error) {
	return gts.cfg.Credential.IdToken, nil
}
