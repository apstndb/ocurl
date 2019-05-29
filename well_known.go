package main

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type wellKnownTokenSource struct{
	creds *google.Credentials
}

func WellKnownTokenSource() (*wellKnownTokenSource, error) {
	if creds, err := wellKnownFileCredentials(context.Background(), defaultScopes...); err == nil {
		return &wellKnownTokenSource{creds}, nil
	} else {
		return nil, err
	}
}

func (wkts *wellKnownTokenSource) Token() (*oauth2.Token, error) {
	return wkts.creds.TokenSource.Token()
}

func (wkts *wellKnownTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	if creds, err := wellKnownFileCredentials(ctx, scopes...); err == nil {
		if token, err := creds.TokenSource.Token(); err == nil {
			return token.AccessToken, nil
		} else {
			return "", err
		}
	} else {
		return "", err
	}
}
