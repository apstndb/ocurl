package main

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"time"
)

func claims(account string, audience string) jwt.Claims {
	now := time.Now().UTC()
	return jwt.StandardClaims{
		Issuer:    account,
		Subject:   account,
		Audience:  audience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
	}
}

func decodeToken(tokenString string) ([]byte, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(&token.Claims, "", "  ")
	if err != nil {
		return nil, err
	}

	return b, nil
}
