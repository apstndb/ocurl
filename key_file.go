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

func newKeyFileTokenSourceFromFile(keyFile string) (*keyFileTokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return newKeyFileTokenSource(buf)
}


func newKeyFileTokenSource(jsonKey []byte) (*keyFileTokenSource, error) {
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

func jwtAccessTokenSource(json []byte, audience string) (oauth2.TokenSource, error) {
	config, err := google.JWTAccessTokenSourceFromJSON(json, audience)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func jwtAccessTokenSourceFromFile(keyFile string, audience string) (oauth2.TokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return jwtAccessTokenSource(buf, audience)
}

func jwtConfigTokenSource(ctx context.Context, json []byte, scopes ...string) (oauth2.TokenSource, error) {
	config, err := google.JWTConfigFromJSON(json, scopes...)
	if err != nil {
		return nil, err
	}
	return config.TokenSource(ctx), err
}

func jwtConfigTokenSourceFromFile(ctx context.Context, keyFile string, scopes ...string) (oauth2.TokenSource, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return jwtConfigTokenSource(ctx, buf, scopes...)
}
