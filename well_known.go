package main

import (
	"context"
	"io/ioutil"

	"golang.org/x/oauth2/google"
)

type wellKnownTokenSource struct {
	wellKnownJSON []byte
}

func WellKnownTokenSource() (TokenSource, error) {
	filename := wellKnownFile()
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return &wellKnownTokenSource{b}, nil
}

func (wkts *wellKnownTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	// TODO google.CredentialsFromJSON take scopes but it seems no effect.
	creds, err := google.CredentialsFromJSON(ctx, wkts.wellKnownJSON, scopes...)
	if err != nil {
		return "", err
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}
