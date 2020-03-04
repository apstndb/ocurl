package main

import (
	"encoding/json"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func sign(claims jwt.Claims, key interface{}) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
}

func claims(account string, audience string, subject string, targetAudience string) jwt.Claims {
	if subject == "" {
		subject = account
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": account,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if targetAudience != "" {
		claims["target_audience"] = targetAudience
	}
	return claims
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
