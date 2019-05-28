package main

import (
	"context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"io/ioutil"
)

type keyFileTokenSource struct {
	jsonKey []byte
	cfg     *jwt.Config
}

func KeyFileTokenSourceFromFile(keyFile string) (*keyFileTokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return KeyFileTokenSource(buf)
}

func KeyFileTokenSource(jsonKey []byte) (*keyFileTokenSource, error) {
	cfg, err := google.JWTConfigFromJSON(jsonKey)
	if err != nil {
		return nil, err
	}

	return &keyFileTokenSource{jsonKey: jsonKey, cfg: cfg}, nil
}

func (kfts *keyFileTokenSource) Email() string {
	return kfts.cfg.Email
}

func (kfts *keyFileTokenSource) Token() (*oauth2.Token, error) {
	token, err := kfts.cfg.TokenSource(context.Background()).Token()
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (kfts *keyFileTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	tokenSource, err := jwtConfigTokenSource(ctx, kfts.jsonKey, scopes...)
	if err != nil {
		return "", err
	}

	token, err := tokenSource.Token()
	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

func (kfts *keyFileTokenSource) IDToken(ctx context.Context, audience string) (string, error) {
	signedJWT, err := signJWTForIdToken(kfts.cfg, audience)
	if err != nil {
		return "", err
	}
	return idTokenImpl(signedJWT)
}

func (kfts *keyFileTokenSource) JWTToken(ctx context.Context, audience string) (string, error) {
	ts, err := jwtAccessTokenSource(kfts.jsonKey, audience)
	if err != nil {
		return "", err
	}

	token, err := ts.Token()
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}
