package main

import (
	"context"
	"io/ioutil"

	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

type keyFileTokenSource struct {
	jsonKey []byte
	cfg     *jwt.Config
}

var _ interface {
	HasAccessToken
	HasIDToken
	HasEmail
	HasJWTToken
} = &keyFileTokenSource{}

func KeyFileTokenSourceFromFile(keyFile string, subject string) (interface {
	HasAccessToken
	HasIDToken
	HasEmail
	HasJWTToken
}, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return KeyFileTokenSource(buf, subject)
}

func KeyFileTokenSource(jsonKey []byte, subject string) (*keyFileTokenSource, error) {
	cfg, err := google.JWTConfigFromJSON(jsonKey)
	if err != nil {
		return nil, err
	}
	cfg.Subject = subject

	return &keyFileTokenSource{jsonKey: jsonKey, cfg: cfg}, nil
}

func (kfts *keyFileTokenSource) Email() (string, error) {
	return kfts.cfg.Email, nil
}

func (kfts *keyFileTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	tokenSource, err := jwtConfigTokenSource(ctx, kfts.jsonKey, kfts.cfg.Subject, scopes...)
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
