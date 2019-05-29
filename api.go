package main

import (
	"context"
	"errors"
	"log"

	"golang.org/x/oauth2"
)

type TokenSource interface{}

type HasAccessTokenWithoutScopes interface {
	TokenSource
	AccessTokenWithoutScopes(ctx context.Context) (string, error)
}

type HasAccessToken interface {
	TokenSource
	AccessToken(ctx context.Context, scopes ...string) (string, error)
}

type HasJWTToken interface {
	TokenSource
	JWTToken(ctx context.Context, audience string) (string, error)
}

type HasIDTokenWithoutAudience interface {
	TokenSource
	IDTokenWithoutAudience(ctx context.Context) (string, error)
}

type HasIDToken interface {
	TokenSource
	IDToken(ctx context.Context, audience string) (string, error)
}

type HasEmail interface {
	TokenSource
	Email() (string, error)
}

func AccessToken(ctx context.Context, tokenSource TokenSource, scopes ...string) (string, error) {
	switch ts := tokenSource.(type) {
	case HasAccessToken:
		return ts.AccessToken(ctx, scopes...)
	case HasAccessTokenWithoutScopes:
		log.Println("fallback to AccessTokenWithoutScopes")
		return ts.AccessTokenWithoutScopes(ctx)
	default:
		return "", errors.New("token source can't issue access token")
	}
}

func IDToken(ctx context.Context, tokenSource TokenSource, audience string) (string, error) {
	switch ts := tokenSource.(type) {
	case HasIDToken:
		return ts.IDToken(ctx, audience)
	case HasIDTokenWithoutAudience:
		log.Println("fallback to IDTokenWithoutAudience")
		return ts.IDTokenWithoutAudience(ctx)
	default:
		return "", errors.New("token source can't issue ID token")
	}
}

func JWTToken(ctx context.Context, tokenSource TokenSource, audience string) (string, error) {
	switch ts := tokenSource.(type) {
	case HasJWTToken:
		return ts.JWTToken(ctx, audience)
	default:
		return "", errors.New("token source can't issue JWT token")
	}
}

func Email(tokenSource TokenSource) (string, error) {
	switch ts := tokenSource.(type) {
	case HasEmail:
		return ts.Email()
	default:
		return "", errors.New("token source hasn't email")
	}
}

func OAuth2TokenSource(ctx context.Context, tokenSource TokenSource, scopes ...string) (oauth2.TokenSource, error) {
	tokenString, err := AccessToken(ctx, tokenSource, scopes...)
	if err != nil {
		return nil, err
	}
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tokenString}), nil
}
