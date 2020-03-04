package main

import (
	"context"

	"golang.org/x/oauth2"
)

type impersonateTokenSource struct {
	sourceTokenSource oauth2.TokenSource
	serviceAccount    string
	delegateChain     []string
}

func ImpersonateTokenSource(sourceTokenSource oauth2.TokenSource, serviceAccount string, delegateChain ...string) *impersonateTokenSource {
	return &impersonateTokenSource{
		sourceTokenSource: sourceTokenSource,
		serviceAccount:    serviceAccount,
		delegateChain:     delegateChain,
	}
}

func (its *impersonateTokenSource) IDToken(ctx context.Context, audience string) (string, error) {
	return impersonateIdToken(ctx, its.sourceTokenSource, its.serviceAccount, its.delegateChain, audience)
}

func (its *impersonateTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	return impersonateAccessToken(ctx, its.sourceTokenSource, its.serviceAccount, its.delegateChain, scopes)
}

func (its *impersonateTokenSource) JWTToken(ctx context.Context, audience string) (string, error) {
	return impersonateJWT(ctx, its.sourceTokenSource, its.serviceAccount, its.delegateChain, claims(its.serviceAccount, audience, "", ""))
}

func (its *impersonateTokenSource) Email() (string, error) {
	return its.serviceAccount, nil
}
