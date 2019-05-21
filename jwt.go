package main

import (
	"context"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
	"time"
)

func claims(account string, audience string) jwt.Claims {
	now := time.Now().UTC()
	return jwt.StandardClaims{
		Issuer: account,
		Subject: account,
		Audience: audience,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}
}

func ImpersonateJWT(ctx context.Context, tokenSource oauth2.TokenSource, serviceAccount string, delegateChain []string, claims jwt.Claims) (string, error) {
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
