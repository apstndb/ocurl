package main

import (
	"cloud.google.com/go/compute/metadata"
	"context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/url"
)

type metadataTokenSource struct {
	account string
}

func newMetadataTokenSource(account string) (*metadataTokenSource, error) {
	return &metadataTokenSource{account: account}, nil
}

func newMetadataTokenSourceDefault() (*metadataTokenSource, error) {
	return newMetadataTokenSource("")
}

func orDefault(v string, def string) string {
	if v == "" {
		return def
	}
	return v
}

func (gts *metadataTokenSource) Token() (*oauth2.Token, error) {
	tokenSource := google.ComputeTokenSource(gts.account)
	return tokenSource.Token()
}

func (gts *metadataTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	tokenSource := google.ComputeTokenSource(gts.account, scopes...)
	token, err := tokenSource.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func (gts *metadataTokenSource) IDToken(ctx context.Context, audience string) (string, error) {
	params := make(url.Values)
	params.Set("audience", audience)
	tokenString, err := metadata.Get("instance/service-accounts/" + orDefault(gts.account, "default") + "/identity?" + params.Encode())
	if err != nil {
		return "", err
	}
	return tokenString, err
}

func (gts *metadataTokenSource) Email(ctx context.Context, audience string) (string, error) {
	tokenString, err := metadata.Get("instance/service-accounts/" + orDefault(gts.account, "default") + "/email")
	if err != nil {
		return "", err
	}
	return tokenString, err
}
