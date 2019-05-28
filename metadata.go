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

func MetadataTokenSource(account string) (*metadataTokenSource, error) {
	return &metadataTokenSource{account: account}, nil
}

func MetadataTokenSourceDefault() (*metadataTokenSource, error) {
	return MetadataTokenSource("")
}

func (mts *metadataTokenSource) Token() (*oauth2.Token, error) {
	tokenSource := google.ComputeTokenSource(mts.account)
	return tokenSource.Token()
}

func (mts *metadataTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	tokenSource := google.ComputeTokenSource(mts.account, scopes...)
	token, err := tokenSource.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func (mts *metadataTokenSource) IDToken(ctx context.Context, audience string) (string, error) {
	params := make(url.Values)
	params.Set("audience", audience)
	tokenString, err := metadata.Get("instance/service-accounts/" + orDefault(mts.account, "default") + "/identity?" + params.Encode())
	if err != nil {
		return "", err
	}
	return tokenString, err
}

func (mts *metadataTokenSource) Email(ctx context.Context, audience string) (string, error) {
	tokenString, err := metadata.Get("instance/service-accounts/" + orDefault(mts.account, "default") + "/email")
	if err != nil {
		return "", err
	}
	return tokenString, err
}
