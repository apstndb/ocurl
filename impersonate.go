package main

import (
	"context"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

type impersonateTokenSource struct {
	sourceTokenSource oauth2.TokenSource
	serviceAccount    string
	delegateChain     []string
}

func newImpersonateTokenSource(sourceTokenSource oauth2.TokenSource, serviceAccount string, delegateChain ...string) *impersonateTokenSource {
	return &impersonateTokenSource{
		sourceTokenSource: sourceTokenSource,
		serviceAccount:    serviceAccount,
		delegateChain:     delegateChain,
	}
}

func (its *impersonateTokenSource) Token() (*oauth2.Token, error) {
	tokenString, err := AccessToken(context.Background(), its)
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: tokenString,
	}, nil
}

func (its *impersonateTokenSource) IDToken(ctx context.Context, audience string) (string, error) {
	return impersonateIdToken(ctx, its.sourceTokenSource, its.serviceAccount, its.delegateChain, audience)
}

func (its *impersonateTokenSource) AccessToken(ctx context.Context, scopes ...string) (string, error) {
	return impersonateAccessToken(ctx, its.sourceTokenSource, its.serviceAccount, its.delegateChain, scopes)
}

func (its *impersonateTokenSource) JWTToken(ctx context.Context, audience string) (string, error) {
	return impersonateJWT(ctx, its.sourceTokenSource, its.serviceAccount, its.delegateChain, claims(its.serviceAccount, audience, ""))
}

func (its *impersonateTokenSource) Email(audience string) (string, error) {
	return its.serviceAccount, nil
}

func impersonateIdToken(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, audience string) (string, error) {
	service, err := iamcredentials.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", err
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.GenerateIdToken(toName(serviceAccount),
		&iamcredentials.GenerateIdTokenRequest{
			Audience:     audience,
			Delegates:    toNames(delegateChain),
			IncludeEmail: true,
		}).Do()
	if err != nil {
		return "", err
	}
	return response.Token, nil
}

func impersonateAccessToken(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, scopes []string) (string, error) {
	service, err := iamcredentials.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", err
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.GenerateAccessToken(toName(serviceAccount),
		&iamcredentials.GenerateAccessTokenRequest{
			Scope:     scopes,
			Delegates: toNames(delegateChain),
		}).Do()
	if err != nil {
		return "", err
	}
	return response.AccessToken, nil
}

func impersonateJWT(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, claims jwt.Claims) (string, error) {
	j, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	service, err := iamcredentials.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", err
	}
	projectsService := iamcredentials.NewProjectsService(service)

	response, err := projectsService.ServiceAccounts.SignJwt(toName(serviceAccount),
		&iamcredentials.SignJwtRequest{
			Delegates: toNames(delegateChain),
			Payload:   string(j),
		}).Do()
	if err != nil {
		return "", err
	}
	return response.SignedJwt, nil
}
